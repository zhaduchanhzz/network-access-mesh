# Runbook Phase 1 — dựng lại tenant thử, edge và gateway VPS của staging

> **File viết tay.** Quy trình dựng (lại) Headscale của các tenant thử A/B theo đúng thứ tự §11.3 của [bản master](../../docs/planning/implementation-master-plan.md), chỉ bằng script trong repo — dùng cho P1-T08/P1-T09 và diễn tập P1-T19; thêm đổi cấu hình tenant/edge và dựng lại gateway VPS (P1-T18). Từ Phase 3, Orchestrator thay thế phần tenant của runbook này.

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
