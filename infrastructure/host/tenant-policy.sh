#!/bin/bash
# Áp một file policy lên Headscale của một tenant dựng tay (Phase 1: fixture P1-T12a, trả về baseline trước P1-T14).
# Cài file vào config/ của instance (root:<run_uid> 0440, mount chỉ-đọc vào /etc/headscale), `policy check`, `policy set`,
# rồi đọc lại và so sha256 với file. Từ Phase 4, policy đi qua pipeline của nền tảng (§7.3), không dùng script này.
#   sudo bash tenant-policy.sh <slug> <policy.hujson>
#   ví dụ: sudo bash tenant-policy.sh tenant-a infrastructure/headscale/templates/test-allow-intra.hujson
#          sudo bash tenant-policy.sh tenant-a infrastructure/headscale/templates/bootstrap-policy.hujson
set -euo pipefail
SLUG=${1:?usage: tenant-policy.sh <slug> <policy.hujson>}; FILE=${2:?policy file}
C=mg-hs-$SLUG
IID=$(docker inspect -f '{{index .Config.Labels "meshguard.instance_id"}}' "$C")
D=/opt/meshguard/tenants/$IID
GID=$(stat -c %g "$D/config")
NAME=$(basename "$FILE")
install -o root -g "$GID" -m 0440 "$FILE" "$D/config/$NAME"
docker exec "$C" headscale policy check --file "/etc/headscale/$NAME" >/dev/null
before=$(docker exec "$C" headscale policy get | head -c -1 | sha256sum | cut -c1-16)
docker exec "$C" headscale policy set --file "/etc/headscale/$NAME" >/dev/null
after=$(docker exec "$C" headscale policy get | head -c -1 | sha256sum | cut -c1-16)
want=$(sha256sum < "$FILE" | cut -c1-16)
[ "$after" = "$want" ] || { echo "LỖI $SLUG: policy đọc lại ($after) khác file ($want)"; exit 1; }
echo "OK   $SLUG: policy $NAME áp xong — sha256 trước $before, sau $after (= file)"
