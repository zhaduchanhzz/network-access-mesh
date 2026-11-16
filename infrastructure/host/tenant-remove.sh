#!/bin/bash
# Gỡ HẲN một Headscale instance dựng tay ở Phase 1 (container, network, thư mục — kể cả dữ liệu và khóa).
# Chỉ dùng cho instance thử (PoC). Bắt buộc cờ xác nhận.  Dùng: sudo bash tenant-remove.sh <slug> --i-understand-this-deletes-data
set -euo pipefail
SLUG=${1:?usage: tenant-remove.sh <slug> --i-understand-this-deletes-data}
[ "${2:-}" = "--i-understand-this-deletes-data" ] || { echo "thiếu cờ xác nhận — không làm gì"; exit 1; }
IID=$(docker inspect -f '{{index .Config.Labels "meshguard.instance_id"}}' "mg-hs-$SLUG" 2>/dev/null || true)
[ -n "$IID" ] || IID=$(docker network inspect -f '{{index .Labels "meshguard.instance_id"}}' "mg-t-$SLUG" 2>/dev/null || true)
[[ "$IID" =~ ^[0-9a-f-]{36}$ ]] || { echo "không xác định được instance_id của $SLUG — dừng"; exit 1; }
D=/opt/meshguard/tenants/$IID
[ -f "$D/compose.yaml" ] && docker compose -f "$D/compose.yaml" down --timeout 60 2>&1 | tail -1
docker network rm "mg-t-$SLUG" >/dev/null 2>&1 || true
rm -rf -- "$D"
echo "đã gỡ $SLUG (instance $IID)"
