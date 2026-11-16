#!/bin/bash
# Tạo một lần các Docker network dùng chung của nền tảng (§14.3) với subnet tĩnh — compose khai báo `external`.
# Dải 10.249.0.0/16 không chồng LAN, pool tenant 10.250.0.0/16, pool Docker 172.24.0.0/13, 100.64.0.0/10.
# Chạy lại an toàn. Dùng: sudo bash networks.sh     Hoàn tác: docker network rm <tên> (khi không còn container nào gắn)
set -euo pipefail
#     tên            subnet           internal
NETS="mg-edge       10.249.0.0/24    no
      mg-data       10.249.1.0/24    yes
      mg-admin      10.249.2.0/24    yes
      mg-obs        10.249.3.0/24    yes
      mg-sec        10.249.4.0/24    yes
      mg-egress     10.249.5.0/24    no
      mg-idp-data   10.249.6.0/24    yes"
while read -r name subnet internal; do
  if docker network inspect "$name" >/dev/null 2>&1; then
    have=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$name")
    [ "$have" = "$subnet" ] || { echo "$name tồn tại với subnet $have (cần $subnet) — dừng"; exit 1; }
    echo "giữ   $name $subnet"
  else
    flags=(); [ "$internal" = yes ] && flags+=(--internal)
    docker network create "${flags[@]}" --subnet "$subnet" --label meshguard.role=platform "$name" >/dev/null
    echo "tạo   $name $subnet$([ "$internal" = yes ] && echo ' (internal)')"
  fi
done <<< "$NETS"
