#!/bin/bash
# Dựng thủ công một Headscale instance (Phase 1 — P1-T08/P1-T09/P1-T11) theo thứ tự §11.3:
#   thư mục (§14.2) → network --internal --subnet <net_cidr> → start → chờ healthy → policy deny-all qua CLI.
# KHÔNG gắn edge (bước riêng, chỉ khi Caddyfile đang chạy đã có allow-list path). KHÔNG tạo API key.
# Đầu vào: thư mục do tools/render_instance.py sinh ra.   Dùng: sudo bash tenant-deploy.sh <rendered_dir>
# Hoàn tác: sudo bash tenant-remove.sh <slug> --i-understand-this-deletes-data
set -euo pipefail
SRC=${1:?usage: tenant-deploy.sh <rendered_dir>}
meta() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SRC/meta/instance.json" "$1"; }
IID=$(meta instance_id); SLUG=$(meta slug); RUID=$(meta run_uid); NET=$(meta net_cidr)
D=/opt/meshguard/tenants/$IID
[ -e "$D" ] && { echo "đã tồn tại: $D — dừng"; exit 1; }
docker ps -a --format '{{.Names}}' | grep -qx "mg-hs-$SLUG" && { echo "container mg-hs-$SLUG đã tồn tại — dừng"; exit 1; }

# 1. thư mục và quyền (§14.2): tiến trình tenant không ghi được vào cây cấu hình
install -d -o root -g "$RUID" -m 0750 "$D" "$D/config" "$D/records"
install -d -o "$RUID" -g "$RUID" -m 0700 "$D/data"
install -d -o root -g root -m 0700 "$D/meta"
install -o root -g "$RUID" -m 0440 "$SRC/config/config.yaml" "$SRC/config/bootstrap-policy.hujson" "$D/config/"
install -o root -g "$RUID" -m 0440 "$SRC/records/extra-records.json" "$D/records/"
install -o root -g root -m 0440 "$SRC/compose.yaml" "$D/compose.yaml"
install -o root -g root -m 0400 "$SRC/meta/instance.json" "$D/meta/instance.json"
echo "1. thư mục: $D"

# 2. network riêng của tenant: internal, subnet tường minh, nhãn instance
docker network create --internal --subnet "$NET" \
  --label "meshguard.instance_id=$IID" --label meshguard.role=tenant "mg-t-$SLUG" >/dev/null
echo "2. network mg-t-$SLUG ($NET, internal)"

# 3. start
docker compose -f "$D/compose.yaml" up -d --quiet-pull 2>&1 | tail -1
echo "3. container mg-hs-$SLUG started"

# 4. chờ healthy (healthcheck start_interval 2s; tối đa 90 s)
for i in $(seq 1 45); do
  st=$(docker inspect -f '{{.State.Health.Status}}' "mg-hs-$SLUG" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  [ "$st" = unhealthy ] && { echo "unhealthy — xem: docker logs mg-hs-$SLUG"; exit 1; }
  sleep 2
done
[ "$st" = healthy ] || { echo "không healthy sau 90 s (trạng thái: $st)"; exit 1; }
echo "4. healthy sau ~$((i * 2)) s"

# 5. policy deny-all qua CLI trong container (Unix socket cục bộ), rồi đọc lại đối chiếu
docker exec "mg-hs-$SLUG" headscale policy set --file /etc/headscale/bootstrap-policy.hujson >/dev/null
got=$(docker exec "mg-hs-$SLUG" headscale policy get -o json | tr -d ' \n\t')
case "$got" in *'"grants":[]'*) echo "5. policy deny-all đã áp và đọc lại khớp";; *) echo "policy đọc lại không khớp — dừng"; exit 1;; esac
