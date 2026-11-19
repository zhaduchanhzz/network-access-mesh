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

Project compose `mg-backup` (`pg-backup`, `idp-backup`, `edge-backup` — lịch riêng, mã hóa tới recipient khôi phục trước khi ghi, file trạng thái cho cảnh báo quá hạn), trigger bắt buộc trước migration, restore PostgreSQL/IdP/volume ACME: [docs/operations/backup-restore.md](../../docs/operations/backup-restore.md). Kích hoạt trên host ở P2-T16, sau nghi thức khóa.

### Restore PostgreSQL về thời điểm cũ hơn — bảo trì + `post-restore-reconcile` (P3-T17, §17.2)

Mọi restore PostgreSQL vào môi trường đang dùng (dump đêm, bộ `pre-migration` khi lùi migration) và mọi restore lên cụm mới là "về thời điểm cũ hơn": registry cũ hơn trạng thái thật của các instance. Trình tự bắt buộc — **bảo trì bật → restore bộ dump → migrate nếu cần → đối soát → rà báo cáo → bảo trì tắt** — và giải thích từng bước, từng khóa của báo cáo: [backup-restore.md mục 6.5](../../docs/operations/backup-restore.md) (phần restore: mục 6.3 bước 2–4, cụm mới: mục 6.4). Lệnh, theo đúng thứ tự:

```bash
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
B=/opt/meshguard/backups/postgres/<id>                                                   # bộ đã chọn (mục 6.1)
$APP exec -T api /usr/local/bin/meshguard admin maintenance on --reason pg-restore       # 1. bảo trì (DB đang dùng)
$APP stop api worker                                                                      # 2. dừng
#   … backup-restore.md mục 6.3 bước 2–4: đổi tên DB hiện tại, globals, pg_restore --create
$APP --profile migrate run --rm -T migrate migrate status || sudo bash infrastructure/host/migrate.sh   # 3. migrate nếu cần
$APP run --rm --no-deps -T api admin maintenance on --reason post-restore                # 4. cờ trong DB VỪA restore
$APP up -d --wait api worker                                                              # 5. khởi động — vẫn 503
RP=$(sudo python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["started_at"])' "$B.manifest.json")
$APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" --dry-run | sudo tee /root/post-restore-dry.json >/dev/null
$APP exec -T worker /usr/local/bin/meshguard admin post-restore-reconcile --restore-point "$RP" | sudo tee /root/post-restore.json >/dev/null   # 7. exit 0/3/1
#   8. rà review_required, incomplete, open_jobs của báo cáo (mục 6.5) — chạy lại bước 7 sau mỗi lần sửa
$APP exec -T api /usr/local/bin/meshguard admin maintenance off                          # 9. mở lại API
sudo docker compose -p mg-backup -f /opt/meshguard/core/compose.backup.yaml run --rm -T pg-backup once --label manual
```

Chế độ bảo trì cũng dùng được riêng (bảo trì có kế hoạch): `meshguard admin maintenance on --reason <mã>` / `off` / `status` — mọi api/worker đọc lại cờ mỗi 5 giây (api `503 maintenance` trừ đăng nhập platform trên `admin.`; worker không chạy job, không lịch), audit `platform.maintenance.enable`/`.disable`. Công tắc lúc khởi động `MG_MAINTENANCE=1`: file override [compose.app.maintenance.yaml](../compose/compose.app.maintenance.yaml). Lệnh đối soát chạy trong container worker (cần Host Agent `MG_AGENT_*` — thiếu thì bước instance/cấp lại key báo `incomplete`, exit 3) và ghi `post_restore` vào cờ; `maintenance off` bị từ chối khi lần chạy cuối của nó chưa xong hoặc lỗi.

### Job `instance.restore` kẹt `failed_resumable` giữ khóa lifecycle (sửa lỗi khóa restore, 2026-11-18)

Trước bản sửa, một restore bị Agent từ chối **trước khi đổi gì** (ví dụ instance dựng tay/adopt chưa kích hoạt: `REFUSAL_REASON_STATE` "only an activated instance with a recorded Noise key fingerprint is restored") dừng `failed_resumable` và giữ khóa lifecycle của tenant — `/rollback` ⇒ `409 kind_not_compensable`, `/cancel` ⇒ `409`, mọi suspend/resume/reconfigure/restart/upgrade/deprovision của tenant bị chặn. Từ bản sửa (api **và** worker cùng bản; Agent mới thêm dấu `Refusal.unchanged`, không bắt buộc cho lối thoát dưới đây), loại lỗi này tự kết thúc `rolled_back`. Job kẹt từ trước bản sửa — lối thoát an toàn:

```bash
J=<job_id>   # job instance.restore failed_resumable
PSQL="sudo docker compose -p mg-core -f /opt/meshguard/core/compose.core.yaml exec -T postgres psql -U postgres -d meshguard -At"
# 1. chỉ đọc: job dừng ở restore.instance, step không ghi gì (worker cũ) — không có step nào sau nó
$PSQL -c "SELECT status, error->>'code', current_step FROM provisioning_jobs WHERE id = '$J'"
$PSQL -c "SELECT seq, name, status, error_code, coalesce(created_resources::text, 'null') FROM provisioning_job_steps WHERE job_id = '$J' ORDER BY seq"
# 2. chỉ đọc: instance có meta/activated không (không có ⇒ Restore chưa bao giờ đổi gì: nó từ chối instance đó đầu tiên)
I=$($PSQL -c "SELECT instance_id FROM provisioning_jobs WHERE id = '$J'")
sudo test -e /opt/meshguard/tenants/$I/meta/activated && echo activated || echo not-activated
# 3. Super Admin trên admin.<domain> (CSRF + Idempotency-Key, quyền platform.job:control):
#    POST /api/v1/platform/jobs/$J/rollback  ⇒ 202 compensating ⇒ GET /api/v1/platform/jobs/$J ⇒ rolled_back
#    (compensation hỏi lại GetInstanceStatus: chưa kích hoạt ⇒ rolled_back; đã kích hoạt ⇒ failed_resumable
#    compensation_failed, khóa vẫn giữ — khi đó /retry hoàn tất restore đã được duyệt 2P, không sửa tay)
# 4. kiểm: không còn job giữ khóa của tenant; audit của restore không có .failed thứ hai
$PSQL -c "SELECT count(*) FROM provisioning_jobs WHERE lock_key = 'tenant:' || (SELECT tenant_id FROM provisioning_jobs WHERE id = '$J') || ':lifecycle' AND status IN ('running', 'compensating', 'failed_resumable')"
```

`/retry` (thay cho bước 3) cũng nhả khóa với instance chưa kích hoạt: `restore.instance` chạy lại, hỏi `GetInstanceStatus` trước ⇒ `instance_not_restorable` ⇒ `rolled_back`. Không xóa/sửa hàng `provisioning_jobs` bằng SQL. Thiết kế: [P3-T11 mục bổ sung](../../docs/planning/evidence/P3-T11.md).

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

### Template v8 → v9 (P4-T01a — SPA sau `app.`/`admin.`): **reload**, không recreate

v9 chỉ đổi Caddyfile (site `app.`/`admin.`: path ngoài `/api/*` ⇒ `web.:8080`, dot segment ⇒ 404, trang lỗi 503, header bảo mật một nguồn); `compose.edge.yaml` chỉ khác dòng chú thích `template_version` ⇒ mục 2 ở trên (reload — loại (a) của §14.6, lên lịch). Thiết kế: [P4-T01a](../../docs/planning/evidence/P4-T01a.md).

```bash
# 0. versions.lock: [images.mg-api], [images.mg-worker], [images.mg-web] pin từ CÙNG một lượt workflow `images` (render_app
#    từ chối nếu thiếu/khác tag). api/worker đổi commit và có migration mới ⇒ sudo bash infrastructure/host/migrate.sh trước.
# 1. web TRƯỚC edge (edge v9 không có web ⇒ app./admin. trả 503 tĩnh)
python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app   # → /opt/meshguard/core/
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
$APP up -d --wait web                                  # (+ api worker nếu đổi image) — healthprobe GET / ⇒ 200
$APP exec -T web /usr/bin/healthprobe http://127.0.0.1:8080/ 200 && echo web-ok
# 2. edge: render, so compose (chỉ dòng template_version), sao lưu, cài, validate, reload
python3 tools/render_edge.py infrastructure/environments/staging/edge.json /tmp/edge
diff /opt/meshguard/core/compose.edge.yaml /tmp/edge/compose.edge.yaml   # chỉ dòng chú thích ⇒ reload
sudo cp -a /opt/meshguard/core/caddy/Caddyfile /root/Caddyfile.v8.$(date +%s)
sudo install -m 0644 /tmp/edge/caddy/Caddyfile /opt/meshguard/core/caddy/Caddyfile
docker exec mg-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec mg-edge caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock
```

3. Kiểm (ngoài các kiểm của mục 5): `https://app.<domain>/` và `/tenants/<id>/devices` qua VPS và LAN-direct ⇒ 200 `text/html` cùng `index.html`, **một** `Content-Security-Policy`, không `Server`; `/api/v1/auth/session` ⇒ 401 `problem+json`; `/healthz`, `/metrics`, `/internal/…` ⇒ `index.html` (không phải body của api); `/.env`, `/api/../metrics` ⇒ 404; `https://admin.<domain>/` từ LAN ⇒ SPA, console Keycloak (`/admin/master/console/`) vẫn sau `forward_auth` (401 khi không có phiên); `run_staging.sh` (nhóm `platform` cần `mg-app-web-1` chạy). Stream long-poll của tenant đóng ~5 phút sau reload (`stream_close_delay`), client tự nối lại.
4. Hoàn tác: cài lại `/root/Caddyfile.v8.<ts>` rồi reload (web để chạy cũng vô hại — không gì định tuyến tới); bỏ web: `$APP stop web && $APP rm -f web`.

### Template v9 → v10 (P4-T07 — chuyển hướng web-auth `/register/<auth_id>`): **reload**, không recreate

v10 chỉ đổi khối `*.<mesh_domain>` của Caddyfile: `GET /register/<auth_id>` (`hskey-authreq-` + 24 ký tự) không có `via=portal` ⇒ `302` tới `https://app.<domain>/enroll/claim?tenant=<slug>&auth_id=<auth_id>`; có `via=portal` ⇒ Headscale như trước; mọi `/register/*` khác ngoài `/register/confirm/*` ⇒ 404. `compose.edge.yaml` chỉ khác dòng chú thích `template_version` ⇒ mục 2 ở trên (reload — loại (a) của §14.6, lên lịch). Thiết kế: [P4-T07](../../docs/planning/evidence/P4-T07.md).

**Điều kiện trước:** api/worker có API claim (P4-T06) và SPA có trang `/enroll/claim` (P4-T08) đã chạy — nếu không, người chạy `tailscale up` không key được đưa tới trang 404 của SPA thay cho trang gốc của Headscale. Các bước: như "Template v8 → v9" bước 2 (render, `diff` compose chỉ dòng `template_version`, sao lưu `Caddyfile.v9.<ts>`, cài, `caddy validate`, reload).

Kiểm (ngoài mục 5, trong đó `run_staging.sh` nhóm `public` đã gồm chuyển hướng, Auth ID sai ⇒ 404 và `via=portal`): một client thật `tailscale up --login-server https://<slug>.mesh.<domain> --hostname mg-<mã>` (mã từ Portal) ⇒ mở link in ra ⇒ trình duyệt tới `app.<domain>/enroll/claim?…` ⇒ claim ⇒ client `Running` (V-07 — theo từng OS); `/key?v=113` A/B/C 200. Hoàn tác: cài lại `/root/Caddyfile.v9.<ts>` rồi reload (link `/register/<auth_id>` lại mở trang gốc của Headscale; phương án "dán Auth ID" vẫn dùng được trong Portal).

## IdP — Keycloak `mg-idp` (P2-T05, triển khai lên staging ở P2-T16)

Project `mg-idp`: `idp` (Keycloak 26.8.2, 3 realm `platform`/`tenant-a`/`tenant-b` nhập lúc khởi động đầu), `idp-db` (PostgreSQL riêng, chỉ trên `mg-idp-data`) và — khi `MG_IDP_MAIL_SINK=mailpit` (staging) — `mailsink` (Mailpit, network `mail` internal: thư không ra ngoài host). Không publish cổng nào; `auth.<domain>` qua edge là bước riêng của P2-T16 (template edge mới + reload có lịch). Thiết kế: [P2-T05](../../docs/planning/evidence/P2-T05.md), [P2-T05b](../../docs/planning/evidence/P2-T05b.md).

Điều kiện: network nền tảng đã có (`networks.sh` — có `mg-edge`, `mg-idp`, `mg-idp-data`, `mg-egress`), edge chạy ở `10.249.0.2` và gắn `mg-idp` ở `10.249.7.2` (proxy tin cậy duy nhất của Keycloak — từ G2 vòng 2 idp chỉ ở `mg-idp`, không còn trên `mg-edge`), `~/mg` là bản đồng bộ **chỉ file tracked** của repo (không bao giờ có `config/secrets/`).

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
- Discovery của 3 realm (từ host, thẳng tới IP của `idp` trên `mg-idp`, cổng 8080): `issuer` = `https://auth.<domain>/realms/<realm>`.
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

## Console quản trị Keycloak — phiên 2P có thời hạn (P3-T15, §8.2 (3))

Console của Keycloak (realm `master`) **chỉ** mở ở `https://admin.<domain>/admin/master/console/` (listener LAN-direct, nguồn trong `admin_allow`), sau `forward_auth` của edge tới api: không có phiên đã duyệt ⇒ 401/403; qua `auth.<domain>` ⇒ 404; qua VPS không có `admin.`. Thiết kế và phép thử: [P3-T15](../../docs/planning/evidence/P3-T15.md).

1. **Super Admin A** đăng nhập Platform Console (mật khẩu + OTP, trong 15 phút) rồi xin phiên — từ đúng máy sẽ mở console (mặc định CIDR = địa chỉ của chính request, /32):
   `POST /api/v1/platform/idp-console/sessions` body `{"reason":"<ticket/sự cố>","duration_minutes":30}` (CSRF + `Idempotency-Key`; `source_cidr` tùy chọn, tối đa /24) ⇒ `202` + `Location: /api/v1/platform/approvals/<id>`.
2. **Super Admin B** (người khác, đăng nhập trong 15 phút) đọc `GET /api/v1/platform/approvals/<id>` (người xin, CIDR, thời hạn, lý do) và duyệt bằng đúng `payload_sha256`: `POST …/approvals/<id>/approve` ⇒ `executed`. Platform Operator không duyệt được (chỉ restore).
3. A mở `https://admin.<domain>/admin/master/console/` trong thời hạn, đăng nhập bằng tài khoản quản trị của realm master (break-glass: `bootstrap-admin-*` của `keycloak.conf`, đi từ kho secret của chủ dự án — không ghi ra đâu). Phiên kết thúc khi hết hạn hoặc khi A đăng xuất Platform Console (cổng đòi phiên đó ở mỗi request).
4. **Mỗi lần đăng nhập** realm master ⇒ `security_event` `idp.console_login` (high) + email `idp.console_login` tới SA/PO (trong ≤ 1 phút — job `idp.audit_sync`; chạy ngay: `docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin idp-audit-sync`). Thay đổi trong console lên realm của tenant ⇒ audit của tenant + email `idp.admin_change` cho Tenant Owner. Impersonation luôn bị chặn (403 + security event critical).
5. Kiểm sau phiên: `GET /api/v1/platform/idp-console/sessions` (trạng thái `ended`), `psql … -c "SELECT kind, severity, occurred_at FROM security_events WHERE kind LIKE 'idp.%' ORDER BY occurred_at DESC LIMIT 20"`.

Đăng nhập realm master **ngoài** quy trình này (kcadm trong container — `realm-update.sh`, `user-id.sh`, `idp-client-secret.sh`, bootstrap) cũng là một lần đăng nhập quản trị và cũng cảnh báo (client `admin-cli`): ghi lý do vào nhật ký vận hành trước khi chạy.

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
$APP up -d --wait api worker web                                  # /readyz: postgres, secretstore, edge_admin; web: healthprobe
```

Từ P4-T01a, `render_app.py` cần `[images.mg-api]`, `[images.mg-worker]` **và** `[images.mg-web]` cùng commit (hoặc cả ba `--api-image --worker-image --web-image`); service `web` (SPA) chỉ trên `mg-edge`, edge template ≥ v9 định tuyến tới nó (mục "Template v8 → v9" ở trên).

## Relay thư ra — `mailrelay` + Worker Cloudflare (P3-T05b-mail)

Email của nền tảng (thông báo của worker, thư của Keycloak, cảnh báo của Alertmanager) đi `mailrelay:587` (network
`mail`, STARTTLS, CA nội bộ) → Worker Cloudflare (HTTPS, HMAC) → Cloudflare Email Service. Thủ tục đầy đủ, lệnh kiểm
và hoàn tác: **[docs/planning/evidence/P3-T05b-mail.md](../../docs/planning/evidence/P3-T05b-mail.md)**, mục 6. Tóm tắt:

```bash
sudo bash infrastructure/host/layout.sh && sudo bash infrastructure/host/networks.sh   # nhóm mg-sec-mail 20009, network mail
sudo bash infrastructure/host/mail-secrets.sh && sudo bash infrastructure/host/check-secrets.sh   # khóa HMAC, CA + cert (không in)
# máy vận hành: render wrangler.toml, deploy, đặt RELAY_HMAC_KEY từ file của host (qua ống, không in), điền MG_MAILRELAY_URL
python3 tools/render_mail.py infrastructure/environments/staging/staging.env infrastructure/mail/cf-worker
python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app   # → /opt/meshguard/core/
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
$APP up -d --wait mail-bridge worker                              # /readyz của cầu: smtp_listener, hmac_key, tls_certificate
```

Xoay: `mail-secrets.sh --rotate-hmac` (ghi tại chỗ — mailrelay dùng ngay; đặt lại `RELAY_HMAC_KEY` của Worker ngay sau đó),
`mail-secrets.sh --rotate-tls` (CA + chứng chỉ mới; khởi động lại mailrelay, worker, idp, alertmanager).

## Điểm vào công khai, capacity, trạng thái của host — `meshguard admin host-set` (P3-T04)

Placement (bước 3 của provisioning) chỉ chọn host `active`, có `public_entry.ipv4` và còn chỗ theo `capacity.max_instances`. Host `mg-staging` do `adopt-instance` đăng ký có `public_entry = {}` ⇒ **trước lần cấp phát đầu** phải khai báo điểm vào công khai (IP của VPS gateway — `MG_PUBLIC_IPV4` của `staging.env`, chế độ `vps_gateway`). Lệnh là cùng thay đổi với `PATCH /api/v1/platform/hosts/{hostId}` (cùng service): kiểm đúng các CHECK của migration 0014, khóa hàng host như placement, đọc `ETag` trước (có thay đổi song song ⇒ lệnh thất bại, không ghi đè), ghi audit `platform.host.update` (giá trị trước/sau, `actor_type=system`, `actor_display = meshguard admin host-set`, request id `admin-<uuid>`). **IP không bao giờ là tham số:** `--public-ipv4-env` nhận **tên** biến môi trường chứa IP (lệnh từ chối một địa chỉ ở vị trí đó); lệnh không in IP. Thiết kế và phép thử: [P3-T04](../../docs/planning/evidence/P3-T04.md) mục 7.

Điều kiện: image `api` đã có lệnh (`meshguard admin` liệt kê `host-set`), migration 0014 đã chạy.

```bash
cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
$APP run --rm --no-deps -T -e "MG_PUBLIC_IPV4=$MG_PUBLIC_IPV4" api admin host-set --name mg-staging \
  --public-ipv4-env MG_PUBLIC_IPV4 --mode vps_gateway
```

Kết quả mong đợi (không có IP):

```text
host-set: host mg-staging (<host id>), region lab
  status: active (unchanged)
  capacity.max_instances: 100 (unchanged)
  public_entry.ipv4: value of $MG_PUBLIC_IPV4 (changed; the address is not printed)
  public_entry.mode: vps_gateway (changed)
  instances not removed: <n> of 100; run UIDs never used: <…>; free /29: <…>
  placement: can choose this host
  audit: platform.host.update (actor_type system, request admin-<uuid>); ETag "<…>"
OK
```

Tùy chọn khác (kết hợp được): `--max-instances <n>` (trần instance chưa `removed`; thấp hơn số instance đang có ⇒ từ chối), `--status draining|disabled|active` (`draining`/`disabled`: placement bỏ qua host, instance đang chạy không bị đụng tới). Chạy lại vô hại (`unchanged`). Mã thoát: `0` xong; `1` bị từ chối hoặc lỗi — thông báo nêu trường và luật, **không ghi gì**; `2` sai cú pháp. Kiểm: `GET /api/v1/platform/hosts?region=lab` (Platform Console, quyền `platform.host:read`) hoặc psql như mục "Kiểm" của adopt với `SELECT name, status, capacity, public_entry ? 'ipv4' AS has_ipv4, public_entry->>'mode' AS mode FROM hosts` (không in IP). Hoàn tác: chạy lại với giá trị cũ (audit giữ giá trị trước của mọi lần đổi), hoặc `--status draining` để placement thôi chọn host.

## Một người rời đi, bị lộ tài khoản hoặc mất thiết bị TOTP — `revoke-sessions` (G2 vòng 2, A-2/A-7)

Khóa user ở Keycloak (`enabled=false`, đăng xuất mọi phiên SSO) **không** chạm phiên BFF của người đó: phiên BFF sống tới hết hạn tuyệt đối (12 h tenant / 8 h nhân sự nền tảng) nếu vẫn có request trong khoảng idle. Đồng bộ tự động sự kiện của IdP (back-channel logout / `idp.audit_sync`) là Phase 6 (§8.2) — tới lúc đó dùng lệnh host-only dưới đây. Lệnh chỉ nhận định danh (id của IdP trong file môi trường, `sub` của user ở IdP — không bao giờ email), ghi **cặp audit** `identity.sessions.revoke.requested` → `.succeeded` (`actor_type=system`, thuộc tenant của người đó hoặc nền tảng) và in số phiên bị thu hồi. Thiết kế và phép thử: [bằng chứng G2](../../docs/planning/evidence/G2-security-review.md), mục "Sửa sau vòng 2".

```bash
cd ~/mg && eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)" && sudo -v
CORE="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
SUB=$(sudo bash infrastructure/idp/user-id.sh tenant-a <username> | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
```

### Offboarding (người rời đi, tài khoản bị chiếm) — theo đúng thứ tự

**Từ P4-T09 (image api/worker có P4-T09, migration `0024`):** Tenant Owner/Admin offboard qua API — `DELETE /api/v1/tenants/{tenantId}/users/{membershipId}` (CSRF; quy tắc 3a: Admin không offboard Owner/Admin khác) ⇒ `202` + `Location` của job `member.offboard`: membership `offboarded`, rời mọi group, identity `disabled`, mọi phiên thu hồi ngay; job expire mọi node + pre-auth key của user `mg-<membership>` và vô hiệu user ở Keycloak. Kiểm: `GET …/users/{membershipId}` ⇒ `offboarding.state = applied` (`failed` ⇒ gọi lại `DELETE` để thử lại). Các bước dưới đây là đường host-only (nhân sự nền tảng; API không dùng được; tài khoản bị chiếm cần chặn trước).

1. **Keycloak** — chặn đăng nhập mới và phiên SSO: Admin Console hoặc `kcadm` trong container (như `user-id.sh`): realm → Users → user → *Enabled* = off, rồi *Sign out* (`POST /admin/realms/<realm>/users/<id>/logout`).
2. **Nền tảng** — thu hồi mọi phiên BFF và khóa danh tính (lần đăng nhập sau bị từ chối `identity_disabled` kể cả khi Keycloak mở lại):

   ```bash
   $CORE run --rm --no-deps -T api admin revoke-sessions --idp "$MG_IDP_ID_TENANT_A" --subject "$SUB"
   ```

   Mong đợi `sessions revoked: <n>`, `status: active → disabled`, `OK`. Với nhân sự nền tảng: `--idp "$MG_IDP_ID_PLATFORM"`. Chạy lại vô hại (`sessions revoked: 0`, `unchanged`).
3. **Thiết bị** — expire thiết bị của người đó (P2-T13, hai pha): `POST /api/v1/tenants/{tenantId}/devices/{deviceId}/expire` (TO/TA, CSRF + `Idempotency-Key`) cho mỗi thiết bị của người đó (`GET …/devices?owner=<membership id>` — trường `owner`); kiểm job `device.revoke` `succeeded`. Membership của người đó giữ nguyên tới khi có API users (P4-T09); identity đã khóa nên membership không dùng được.
4. **Kiểm**: `psql … -c "SELECT action, outcome FROM audit_events WHERE resource_id = '<identity id in ra>' ORDER BY occurred_at"` ⇒ cặp `identity.sessions.revoke.*`; người đó gọi `GET /api/v1/auth/session` bằng cookie cũ ⇒ 401.

Hoàn tác (khóa nhầm, người quay lại): `$CORE run --rm --no-deps -T api admin enable-identity --idp <id> --subject "$SUB"` (audit `identity.enable`; không hồi sinh phiên cũ, không đụng membership hay tài khoản Keycloak — bật lại user ở Keycloak riêng).

### Mất thiết bị TOTP (hoặc nghi lộ mật khẩu) — khôi phục, không khóa

1. **Xác minh danh tính ngang mức lúc cấp tài khoản** (ASVS 6.4.4) — không bao giờ chỉ qua kênh vừa liên lạc tới: gọi lại qua số/kênh đã biết từ trước; với **nhân sự nền tảng** cần **hai người vận hành** cùng xác nhận (2P). Ghi ticket (ai yêu cầu, ai xác minh, kênh nào) — không ghi mã, mật khẩu hay seed TOTP.
2. **Keycloak**: realm → Users → user → tab *Credentials* → xóa credential `otp`; *Required user actions* thêm `Configure OTP` (và `Update Password` nếu nghi lộ mật khẩu — đặt mật khẩu tạm qua kênh riêng); *Sign out* mọi phiên.
3. **Nền tảng** — thu hồi mọi phiên BFF nhưng **không** khóa (người đó đăng nhập lại và đăng ký TOTP mới):

   ```bash
   $CORE run --rm --no-deps -T api admin revoke-sessions --idp <id> --subject "$SUB" --keep-enabled
   ```

4. Thiết bị đã enroll vẫn hợp lệ (node key không phụ thuộc TOTP); nếu thiết bị mất là laptop/điện thoại đã enroll ⇒ expire nó như bước 3 của offboarding.

### Phiên đồng thời (ASVS 7.1.2)

Không giới hạn số phiên BFF của một người (Portal web + Console, nhiều trình duyệt). Mỗi phiên hiện ở `GET /api/v1/auth/sessions` (thời điểm tạo, lần dùng cuối, IP, user agent); chính người đó thu hồi phiên lạ bằng `DELETE /api/v1/auth/sessions/{id}` (không đòi xác thực lại — chấp nhận ở §23, A-5) hoặc đăng xuất. Người vận hành thu hồi **mọi** phiên của một người bằng `revoke-sessions` ở trên; thu hồi mọi phiên của mọi người sau restore — `post-restore-reconcile` ([backup-restore.md](../../docs/operations/backup-restore.md) mục 6.5); sự cố khóa không kèm restore — `revoke-sessions` từng người. Cảnh báo khi số phiên vượt ngưỡng: Phase 6 (giám sát).

## Monitoring và cảnh báo tối thiểu `mg-obs` (P3-T16)

Project compose **`mg-obs`** (render bằng `tools/render_monitoring.py`): `prometheus`, `alertmanager`, `node-exporter` (node_exporter v1.12.1 build lại từ nguồn — `[sources.node-exporter]`), `prober` (P3-T03a: RPC của worker trên `mg-admin` `10.249.2.3:8080` + `/probe` cho Prometheus) và `alertsink` (kênh cảnh báo nội bộ). Không cổng nào publish; không đổi firewall host. Thiết kế, phép thử và diễn tập: [P3-T16](../../docs/planning/evidence/P3-T16.md).

### Điều kiện

- `~/mg` ở commit đã gộp P3-T16; workflow `images` xanh trên commit đó và `versions.lock` đã pin **cùng commit** `[images.mg-probe]` (bản có `/probe` + `alertsink`) và `[images.mg-node-exporter]` (mới). `render_monitoring.py` từ chối khi thiếu pin.
- `networks.sh` đã tạo `mg-edge`, `mg-admin`, `mg-obs`, `mg-egress`; edge template ≥ v8 (listener metrics `10.249.3.2:9091`); project `mg-backup` đang chạy (status.prom).

### Triển khai

```bash
cd ~/mg
sudo bash infrastructure/host/layout.sh                     # thêm core/monitoring/{prometheus/{rules,targets},alertmanager,drill}
sudo bash infrastructure/host/obs-secrets.sh check          # edge_metrics_token có sẵn (P1-T03); kênh ngoài: "không có"
sudo bash infrastructure/host/check-secrets.sh              # mọi dòng PASS (SKIP cho kênh chưa bật)
python3 tools/render_monitoring.py infrastructure/environments/staging/staging.env /tmp/mg-obs
M=/opt/meshguard/core/monitoring
sudo install -m 0644 /tmp/mg-obs/compose.monitoring.yaml /opt/meshguard/core/compose.monitoring.yaml
sudo install -m 0644 /tmp/mg-obs/monitoring/prometheus/prometheus.yml $M/prometheus/
sudo install -m 0644 /tmp/mg-obs/monitoring/prometheus/rules/meshguard.rules.yml $M/prometheus/rules/
sudo install -m 0644 /tmp/mg-obs/monitoring/alertmanager/alertmanager.yml $M/alertmanager/
sudo bash infrastructure/host/obs-targets.sh install         # timer mg-obs-targets (mỗi phút) + lượt đầu: "2 instance(s)"
OBS="sudo docker compose -p mg-obs -f /opt/meshguard/core/compose.monitoring.yaml"
$OBS up -d --wait --wait-timeout 180                         # prometheus, alertmanager, prober, alertsink healthy
```

Kiểm (đọc qua một container dùng-một-lần trên `mg-obs` — image alpine pin của `versions.lock`):

```bash
A=docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
sudo docker run --rm --network mg-obs $A wget -qO- http://10.249.3.3:9090/api/v1/targets > /tmp/targets.json
python3 -c 'import json; t=json.load(open("/tmp/targets.json"))["data"]["activeTargets"]; print(len(t), "targets; down:", [(x["labels"]["job"], x["labels"].get("instance"), x["lastError"]) for x in t if x["health"] != "up"])'
# mong đợi: 16 targets (prometheus, alertmanager, node, prober, alertsink, api, worker, 2 headscale, 2 probe-key-edge,
# 2 probe-key-public, 3 probe-tls), danh sách down rỗng
sudo docker logs mg-obs-alertsink-1 2>&1 | grep -c '"alert notification"'   # cảnh báo đang có (nếu có) đã tới kênh
```

### Nối prober cho worker (`MG_PROBER_URL`)

`staging.env` có `MG_PROBER_URL=http://10.249.2.3:8080` (địa chỉ tĩnh của prober trên `mg-admin` — `render_app.py` từ chối mọi giá trị khác, kể cả tên container: tên có thể phân giải ra địa chỉ `mg-edge` và lời gọi bị `caller_not_allowed` — P3-T05c). Sau khi `mg-obs` healthy:

```bash
python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app
sudo cp /opt/meshguard/core/compose.app.yaml /root/compose.app.yaml.$(date -u +%Y%m%dT%H%M%SZ)   # bản cũ để hoàn tác
sudo install -m 0644 /tmp/mg-app/compose.app.yaml /opt/meshguard/core/compose.app.yaml
APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
$APP up -d --wait worker
$APP logs --since 5m worker | grep -c 'relay.probe is not run'                                    # 0
eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)"
P=$(python3 -c 'import tomllib; i=tomllib.load(open("versions.lock","rb"))["images"]["mg-probe"]; print(i["image"]+"@"+i["index"])')
echo "{\"address\":\"10.249.0.2:443\",\"host\":\"tenant-a.mesh.$MG_BASE_DOMAIN\"}" | sudo docker run --rm -i \
  --network container:$($APP ps -q worker) --read-only --cap-drop ALL --user 65532:65532 $P call --url "$MG_PROBER_URL" edge \
  | grep -E '"ok"|"blocked"'                                                                       # ok true, blocked 22
```

Từ đây `relay.probe` chạy theo lịch (region `embedded` có instance chạy — A/B adopt chưa có hàng relay tới P3-T14b) và bước 17/18 của `POST /platform/tenants` không còn dừng vì thiếu prober.

### Kênh cảnh báo

Mặc định staging: **alertsink** (webhook nội bộ trên `mg-obs`, giữ 1000 thông báo trong bộ nhớ) — đọc `sudo docker logs mg-obs-alertsink-1 2>&1 | grep '"alert notification"'` hoặc `wget -qO- http://10.249.3.7:8080/v1/notifications` từ container trên `mg-obs`. Không gửi tới người.

- **E-mail (Cloudflare Email Service qua cầu SMTP `mailrelay`)** — khi project của cầu đã chạy (service `mailrelay:587` trên network `mail`, STARTTLS với CA nội bộ `/opt/meshguard/secrets/mail/ca.crt`; file CA phải đọc được bởi UID 65534 hoặc nhóm `mg-sec-obs` 20006 — chỉ chứng chỉ, không khóa): điền `MG_ALERT_EMAIL_TO=<địa chỉ,…>` (người gửi `MG_SMTP_FROM`, mặc định `MeshGuard <no-reply@MG_BASE_DOMAIN>`) trong `staging.env`, render + cài như mục Triển khai (compose + `alertmanager.yml`), `$OBS up -d alertmanager` (alertmanager nối thêm network `mail`). Thử: `$OBS exec -T alertmanager amtool alert add DrillEmail severity=warning drill=1 --annotation=summary="thử kênh e-mail" --alertmanager.url=http://127.0.0.1:9093` ⇒ thư tới trong ~30 s (+ bản ghi ở alertsink). Relay khác: `MG_ALERT_SMTP_SMARTHOST=host:port` (+ `MG_ALERT_SMTP_CA_FILE`, `MG_ALERT_SMTP_USERNAME`, mật khẩu: `sudo bash infrastructure/host/obs-secrets.sh set smtp_password < file-tạm`).
- **Telegram**: `sudo bash infrastructure/host/obs-secrets.sh set telegram_bot_token < file-tạm`, `MG_ALERT_TELEGRAM_CHAT_ID=<id>`, render + cài + `up -d alertmanager`.
- **Webhook ngoài** (Slack/Teams/…): `sudo bash infrastructure/host/obs-secrets.sh set alert_webhook_url < file-tạm` (URL https có token), `MG_ALERT_WEBHOOK=on`, render + cài + `up -d alertmanager`.
- Kênh ra ngoài host đi qua `mg-egress` (e-mail qua `mail`); không credential nào nằm trong file render (chỉ `*_file`). `AlertmanagerNotificationsFailing` báo khi một kênh gửi lỗi. Giữ alertsink cho diễn tập (`MG_ALERT_SINK=on`).

### Diễn tập (mỗi rule bắn một lần, thông báo tới kênh)

```bash
sudo python3 tools/render_monitoring.py drill all /opt/meshguard/core/monitoring --step 70   # 11 file diễn tập, nhãn drill="1"
sleep 240                                                                                       # `for` dài nhất 2 phút + nhóm 30 s
sudo docker logs --since 10m mg-obs-alertsink-1 2>&1 | grep '"alert notification"' | grep '"drill":"1"' \
  | grep -o '"alertname":"[A-Za-z]*"' | sort -u        # 14 rule (danh sách: P3-T16 mục 6)
sudo python3 tools/render_monitoring.py drill clear /opt/meshguard/core/monitoring               # ⇒ thông báo resolved
$OBS stop node-exporter && sleep 180 && $OBS start node-exporter                                 # PlatformTargetDown{job=node}
sudo mv /opt/meshguard/backups/idp/status.prom /root/idp-status.prom.drill && sleep 720 \
  && sudo mv /root/idp-status.prom.drill /opt/meshguard/backups/idp/status.prom                  # PlatformBackupStatusMissing{target=idp}
```

`HostRebooted` diễn tập (`drill="1"`) không nén cảnh báo thật (inhibition chỉ nhận nguồn không có nhãn diễn tập). Không dừng instance thật của tenant để diễn tập — instance ma `drill-ghost` (đích giả `targets/drill-instance.json`) cho đúng hai rule đó.

### Cảnh báo (P3-T16) — ý nghĩa và việc đầu tiên

| Rule | Mức | Việc đầu tiên |
|---|---|---|
| `TenantInstanceDown` | critical | `docker ps -a --filter name=mg-hs-<slug>`; log Agent (start guard từ chối? `edge_attach`?); edge còn gắn `mg-t-<slug>` (`reattach-edge.sh`) |
| `TenantControlProbeFailed` | critical | `via=edge`: như trên; `via=public`: VPS/tunnel/DNS (`tools/health_probe.py`, `wg show`) |
| `CertificateExpiringSoon` | high | log ACME của edge (`docker logs mg-edge`, tìm `acme`): DNS-01, token DNS, CAA |
| `PlatformBackupOverdue`, `PlatformBackupFailing`, `PlatformBackupStatusMissing` | high | `docker compose -p mg-backup … run --rm <dịch vụ> status` (pg-backup, idp-backup, edge-backup); log dịch vụ; [backup-restore](../../docs/operations/backup-restore.md) mục 2 |
| `TenantBackupOverdue` | high | job `instance.backup` lỗi của tenant (`GET /platform/backups?instance_id=`), Host Agent, `MG_BACKUP_MANIFEST_PUBKEY` |
| `NodeFilesystemAlmostFull` | high | `df -h`; retention backup (§17.1), log container, image cũ (`docker image ls`) — không xóa dữ liệu tenant |
| `HostRebooted` | warning | chỉ để nén cảnh báo tenant 10 phút sau boot; kiểm instance lên đủ sau cửa sổ |
| `PlatformTargetDown` | high | `docker compose -p <project> ps` của job tương ứng; `probe-*` ⇒ prober |
| `AlertmanagerNotificationsFailing` | high | log alertmanager; secret kênh (`obs-secrets.sh check`); cầu `mailrelay` / đường ra `mg-egress` |
| `ReconcileNoiseKeyMismatch` | critical | không start lại instance; báo cáo `instance.reconcile`, `security_events` `reconcile.noise_key_mismatch`; restore (§17.2) |
| `ReconcileSecurityDrift` | high | báo cáo reconcile + `security_events` `reconcile.<kind>`; reconcile không tự sửa |
| `InstanceAPIKeyExpiringSoon` | high | job `apikey.rotate` lỗi của tenant; chạy tay `meshguard-worker admin apikey-rotate` |
| `IdPConsoleLogin` | high | đối chiếu phiên console 2P (mục "Console quản trị Keycloak"); không có phiên đã duyệt ⇒ sự cố |
| `IdPAuditSyncStale` | high | `meshguard_idp_audit_sync_failures_total{reason}`; chạy tay `admin idp-audit-sync` |

Giới hạn đã biết: log Critical của start guard (Agent `network_mode: none`) không có đường metrics — hệ quả của nó lộ qua `TenantInstanceDown` (≤ 2 phút) và `ReconcileNoiseKeyMismatch`; số liệu network của host không có (node-exporter ở netns riêng trên `mg-obs`); HTTP SD từ api, cAdvisor, Grafana, Loki: P6-T01.

### Hoàn tác

```bash
$OBS down                                                    # dữ liệu Prometheus/Alertmanager giữ trong volume (down -v để xóa)
sudo systemctl disable --now mg-obs-targets.timer
sudo rm -f /etc/systemd/system/mg-obs-targets.* /usr/local/sbin/mg-obs-targets && sudo systemctl daemon-reload
sudo install -m 0644 /root/compose.app.yaml.<ts> /opt/meshguard/core/compose.app.yaml && $APP up -d worker   # worker không prober
```
