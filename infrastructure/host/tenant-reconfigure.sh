#!/bin/bash
# Áp cấu hình render MỚI cho một instance đang chạy (Phase 1; luồng Reconfigure ở §11.4): `configtest` trong container
# tạm với thư mục dữ liệu nháp (RT-05) → giữ bản cũ trong meta/ → thay config.yaml + meta/instance.json → restart có
# kiểm soát → chờ healthy → policy (nằm trong DB) phải giữ nguyên. Đổi cấu hình Headscale bắt buộc restart (RT-04):
# client của tenant mất control vài giây rồi tự nối lại (P1-T13).
#   sudo bash tenant-reconfigure.sh <rendered_dir>
# Hoàn tác: chép meta/config.yaml.bak-<ts> về config/config.yaml (root:<run_uid> 0440) rồi docker restart mg-hs-<slug>
set -euo pipefail
SRC=${1:?usage: tenant-reconfigure.sh <rendered_dir>}
meta() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SRC/meta/instance.json" "$1"; }
IID=$(meta instance_id); SLUG=$(meta slug); RUID=$(meta run_uid); IMAGE=$(meta image)
D=/opt/meshguard/tenants/$IID; C=mg-hs-$SLUG
[ -d "$D" ] || { echo "không có instance $IID — dùng tenant-deploy.sh"; exit 1; }
if cmp -s "$SRC/config/config.yaml" "$D/config/config.yaml"; then echo "$SLUG: config không đổi — không làm gì"; exit 0; fi

# 1. configtest trên bản mới, dữ liệu nháp (không bao giờ trỏ vào data/ đang chạy)
docker run --rm --network none --read-only --user "$RUID:$RUID" --tmpfs /var/lib/headscale:uid="$RUID",gid="$RUID" \
  --tmpfs /var/run/headscale:uid="$RUID",gid="$RUID" -v "$SRC/config/config.yaml:/etc/headscale/config.yaml:ro" \
  "$IMAGE" configtest >/dev/null 2>&1 || { echo "configtest THẤT BẠI — không thay gì"; exit 1; }
echo "1. configtest (dữ liệu nháp): ok"

# 2. giữ bản cũ, thay bản mới
ts=$(date -u +%Y%m%dT%H%M%SZ)
install -o root -g root -m 0400 "$D/config/config.yaml" "$D/meta/config.yaml.bak-$ts"
before=$(docker exec "$C" headscale policy get | sha256sum | cut -c1-16)
install -o root -g "$RUID" -m 0440 "$SRC/config/config.yaml" "$D/config/config.yaml"
install -o root -g root -m 0400 "$SRC/meta/instance.json" "$D/meta/instance.json"
echo "2. config mới đã cài (bản cũ: meta/config.yaml.bak-$ts)"

# 3. restart có kiểm soát, chờ healthy
s=$(date +%s%3N); docker restart -t 10 "$C" >/dev/null
for _ in $(seq 1 90); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$C")" = healthy ] && break; sleep 1; done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$C")" = healthy ] || { echo "không healthy — hoàn tác bằng bản cũ"; exit 1; }
echo "3. restart: healthy sau $(( $(date +%s%3N) - s )) ms"

# 4. policy giữ nguyên
after=$(docker exec "$C" headscale policy get | sha256sum | cut -c1-16)
[ "$before" = "$after" ] && echo "4. policy giữ nguyên ($after)" || { echo "4. POLICY ĐỔI: $before → $after"; exit 1; }
