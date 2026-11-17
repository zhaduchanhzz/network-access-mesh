#!/bin/bash
# Đổi IMAGE Headscale của một instance đang chạy — luồng Upgrade của §11.4 rút gọn cho Phase 1 (P2-T10a: image chính
# thức ⇄ bản vá mg-headscale, cùng v0.29.7). Đầu vào: thư mục do tools/render_instance.py sinh ra, CHỈ khác bản đang
# chạy ở image (config.yaml phải trùng — đổi config dùng tenant-reconfigure.sh, mỗi lần một thay đổi).
#   pull digest đích → ghi policy/số node/số user → dừng → cold backup data/ vào meta/backup-<ts>/ → `configtest` của image
#   đích trên BẢN SAO backup, không network (mở + migrate DB — RT-05) → cài compose.yaml/meta mới (giữ bản cũ) →
#   compose up -d (tạo lại container) → chờ healthy → khẳng định image đang chạy = đích, policy/node/user không đổi.
# Client của tenant mất control trong lúc dừng (vài giây) rồi tự nối lại; tunnel P2P đang có không bị cắt.
#   sudo bash tenant-upgrade.sh <rendered_dir>
# Hoàn tác: chạy lại script với thư mục render của image cũ (DB v0.29.7 dùng được cho cả hai bản — contract test
#   P2-T10a thử hai chiều). Nếu instance không lên: compose down; thay data/ bằng meta/backup-<ts>/data (giữ owner);
#   cài meta/compose.yaml.bak-<ts> và meta/instance.json.bak-<ts> về chỗ cũ; compose up -d.
set -euo pipefail
SRC=${1:?usage: tenant-upgrade.sh <rendered_dir>}
meta() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SRC/meta/instance.json" "$1"; }
IID=$(meta instance_id); SLUG=$(meta slug); RUID=$(meta run_uid); IMAGE=$(meta image)
D=/opt/meshguard/tenants/$IID; C=mg-hs-$SLUG
[ -d "$D" ] || { echo "không có instance $IID — dùng tenant-deploy.sh"; exit 1; }
cmp -s "$SRC/config/config.yaml" "$D/config/config.yaml" || {
  echo "config.yaml khác bản đang chạy — đổi config bằng tenant-reconfigure.sh trước (mỗi lần một thay đổi)"; exit 1; }
CUR=$(docker inspect -f '{{.Config.Image}}' "$C")
[ "$CUR" != "$IMAGE" ] || { echo "$SLUG: đang chạy đúng $IMAGE — không làm gì"; exit 0; }
echo "$SLUG: $CUR → $IMAGE"

# 1. image đích có trên host (digest pin — pull nếu chưa có)
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null
echo "1. image đích: có"

# 2. trạng thái trước khi đổi
count() { docker exec "$C" headscale "$1" list -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))'; }
pol_before=$(docker exec "$C" headscale policy get | sha256sum | cut -c1-16)
nodes_before=$(count nodes); users_before=$(count users)
echo "2. trước: policy $pol_before, $nodes_before node, $users_before user — $(docker exec "$C" headscale version | head -2 | tr '\n' ' ')"

# 3. dừng + cold backup (đúng hướng dẫn upstream: sao chép khi đã dừng)
ts=$(date -u +%Y%m%dT%H%M%SZ)
docker compose -f "$D/compose.yaml" stop -t 60 2>&1 | tail -1
install -d -o root -g root -m 0700 "$D/meta/backup-$ts"
cp -a "$D/data" "$D/meta/backup-$ts/data"
echo "3. đã dừng; cold backup: meta/backup-$ts/data"

# 4. preflight: configtest của image đích trên BẢN SAO dữ liệu, không network
tmp=$(mktemp -d)
cp -a "$D/meta/backup-$ts/data" "$tmp/data"
if ! docker run --rm --network none --read-only --user "$RUID:$RUID" \
     --tmpfs /var/run/headscale:uid="$RUID",gid="$RUID" -v "$D/config:/etc/headscale:ro" \
     -v "$D/records:/etc/headscale-records:ro" -v "$tmp/data:/var/lib/headscale" "$IMAGE" configtest >/dev/null 2>&1; then
  rm -rf "$tmp"
  docker compose -f "$D/compose.yaml" start 2>&1 | tail -1
  echo "4. configtest của image đích THẤT BẠI trên bản sao dữ liệu — đã start lại image cũ, không đổi gì"; exit 1
fi
rm -rf "$tmp"
echo "4. configtest (image đích, bản sao dữ liệu, không network): ok"

# 5. cài compose/meta mới (giữ bản cũ), tạo lại container
install -o root -g root -m 0400 "$D/compose.yaml" "$D/meta/compose.yaml.bak-$ts"
install -o root -g root -m 0400 "$D/meta/instance.json" "$D/meta/instance.json.bak-$ts"
install -o root -g root -m 0440 "$SRC/compose.yaml" "$D/compose.yaml"
install -o root -g root -m 0400 "$SRC/meta/instance.json" "$D/meta/instance.json"
s=$(date +%s%3N)
docker compose -f "$D/compose.yaml" up -d --quiet-pull 2>&1 | tail -1
echo "5. compose.yaml mới đã cài (bản cũ: meta/compose.yaml.bak-$ts), container tạo lại"

# 6. chờ healthy
st=missing
for _ in $(seq 1 45); do
  st=$(docker inspect -f '{{.State.Health.Status}}' "$C" 2>/dev/null || echo missing)
  [ "$st" = healthy ] && break
  sleep 2
done
[ "$st" = healthy ] || { echo "6. KHÔNG healthy ($st) — hoàn tác theo đầu file"; exit 1; }
echo "6. healthy sau $(( $(date +%s%3N) - s )) ms"

# 7. khẳng định
run=$(docker inspect -f '{{.Config.Image}}' "$C")
pol_after=$(docker exec "$C" headscale policy get | sha256sum | cut -c1-16)
nodes_after=$(count nodes); users_after=$(count users)
echo "7. sau: image $run; policy $pol_after, $nodes_after node, $users_after user — $(docker exec "$C" headscale version | head -2 | tr '\n' ' ')"
if [ "$run" != "$IMAGE" ] || [ "$pol_after" != "$pol_before" ] || [ "$nodes_after" != "$nodes_before" ] || [ "$users_after" != "$users_before" ]; then
  echo "7. LỆCH so với trước khi đổi — kiểm tra rồi hoàn tác theo đầu file"; exit 1
fi
echo "7. ok: image đích đang chạy; policy, node, user giữ nguyên"
