#!/bin/bash
# P5-T09 (§18.1 T-05, AC-20): quét allow-list của edge trên MỌI tenant đang chạy của host — không phải danh sách viết
# tay. Liệt kê container mg-hs-<slug> đang chạy (nhãn meshguard.tenant_id của template instance), in số tenant, rồi
# chạy run_staging.sh với toàn bộ slug. Không đổi gì ngoài những gì run_staging.sh đã làm (network/holder tạm, API key
# hạn 1 giờ expire ngay, dọn sạch khi thoát).
#   sudo bash tests/security/edge/all_tenants_staging.sh <mesh_domain> <public_entry_ipv4>
# Từ máy ngoài nền tảng, cùng danh sách: python3 -I tests/security/edge/external.py <ip> <mesh_domain> <slug,slug,…>
#   --admin-public  (dòng lệnh in ở cuối).
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
DOMAIN=${1:?usage: all_tenants_staging.sh <mesh_domain> <public_entry_ipv4>}; ENTRY=${2:?public entry ip}
mapfile -t SLUGS < <(docker ps --filter label=meshguard.tenant_id --filter status=running --format '{{.Names}}' |
  sed -n 's/^mg-hs-\([a-z0-9][a-z0-9-]*\)$/\1/p' | sort -u)
[ "${#SLUGS[@]}" -gt 0 ] || { echo "không có tenant nào đang chạy (mg-hs-*)" >&2; exit 2; }
echo "== ${#SLUGS[@]} tenant đang chạy: ${SLUGS[*]}"
rc=0
bash "$DIR/run_staging.sh" "$DOMAIN" "$ENTRY" "${SLUGS[@]}" || rc=$?
echo "== external (chạy từ máy ngoài nền tảng): python3 -I tests/security/edge/external.py <public_ipv4> <mesh_domain>" \
  "$(IFS=,; echo "${SLUGS[*]}") --admin-public"
exit $rc
