#!/bin/bash
# Gắn edge vào network riêng của các instance đã qua bước policy deny-all (P1-T08; §11.3 bước 12 → 14).
# Network tenant được gắn lúc chạy (thêm tenant không reload Caddy — §14.6), compose của edge không quản lý chúng,
# nên phải chạy lại script này sau mỗi lần recreate edge ở Phase 1–2. Sau khi gắn, kiểm network có ĐÚNG hai thành
# viên: Headscale của tenant + edge. Instance chưa có dấu meta/policy-bootstrap.ok (tenant-deploy.sh bước 5) bị bỏ qua.
# Dùng: sudo bash reattach-edge.sh [slug ...]      (không có slug: mọi instance)   Thoát khác 0 nếu có lỗi.
# Hoàn tác (một tenant): docker network disconnect mg-t-<slug> mg-edge
set -euo pipefail
EDGE=mg-edge
docker inspect "$EDGE" >/dev/null 2>&1 || { echo "không có container $EDGE"; exit 1; }
fail=0
for meta in /opt/meshguard/tenants/*/meta/instance.json; do
  [ -e "$meta" ] || continue
  d=$(dirname "$(dirname "$meta")")
  slug=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["slug"])' "$meta")
  if [ $# -gt 0 ] && [[ " $* " != *" $slug "* ]]; then continue; fi
  net=mg-t-$slug
  if [ ! -s "$d/meta/policy-bootstrap.ok" ]; then echo "bỏ qua $slug: chưa qua bước policy deny-all"; continue; fi
  if ! docker network inspect "$net" >/dev/null 2>&1; then echo "LỖI  $slug: không có network $net"; fail=1; continue; fi
  members() { docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$net" | xargs -n1 | sort | xargs; }
  if members | grep -qw "$EDGE"; then st="đã gắn"; else docker network connect "$net" "$EDGE"; st="gắn mới"; fi
  want=$(printf '%s\n' "$EDGE" "mg-hs-$slug" | sort | xargs)
  got=$(members)
  if [ "$got" = "$want" ]; then echo "OK   $slug ($st): $got"; else echo "LỖI  $slug: thành viên '$got' (cần '$want')"; fail=1; fi
done
exit $fail
