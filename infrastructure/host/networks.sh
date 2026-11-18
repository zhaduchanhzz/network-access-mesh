#!/bin/bash
# Tạo một lần các Docker network dùng chung của nền tảng (§14.3) với subnet tĩnh — compose khai báo `external`.
# Dải 10.249.0.0/16 không chồng LAN, pool tenant 10.250.0.0/16, pool Docker 172.24.0.0/13, 100.64.0.0/10.
# Network có thành viên IP tĩnh (edge: .2 — compose.edge.yaml) cấp IP động chỉ trong nửa trên (`--ip-range` .128/25)
# để container khởi động trước edge không chiếm mất IP tĩnh của edge.
# mg-idp (G2 vòng 2, A-8): CHỈ edge (10.249.7.2) và idp — không thành viên nào khác của mg-edge (api, worker, …) tới
# được idp:8080; Keycloak chỉ tin X-Forwarded-* từ 10.249.7.2 (KC_PROXY_TRUSTED_ADDRESSES).
# mail (P3-T05b-mail — tên đúng như khóa compose `mail` của mg-app, mg-idp, mg-obs): relay thư ra — mailrelay (SMTP 587 chỉ nghe trên địa chỉ của nó ở đây),
# worker, idp, alertmanager; internal: đường ra Internet của mailrelay là mg-egress.
# Chạy lại an toàn. Dùng: sudo bash networks.sh     Hoàn tác: docker network rm <tên> (khi không còn container nào gắn)
set -euo pipefail
#     tên            subnet           internal  ip-range (cấp động)
NETS="mg-edge       10.249.0.0/24    no        10.249.0.128/25
      mg-data       10.249.1.0/24    yes       -
      mg-admin      10.249.2.0/24    yes       10.249.2.128/25
      mg-obs        10.249.3.0/24    yes       10.249.3.128/25
      mg-sec        10.249.4.0/24    yes       -
      mg-egress     10.249.5.0/24    no        -
      mg-idp-data   10.249.6.0/24    yes       -
      mg-idp        10.249.7.0/24    yes       10.249.7.128/25
      mail          10.249.8.0/24    yes       -"
while read -r name subnet internal range; do
  if docker network inspect "$name" >/dev/null 2>&1; then
    # JSON thay cho template: với Docker 29, IPRange rỗng in ra "invalid Prefix" qua --format
    have=$(docker network inspect "$name" | python3 -c 'import json, sys
c = json.load(sys.stdin)[0]["IPAM"]["Config"][0]
print(c.get("Subnet", ""), c.get("IPRange") or "-")')
    [ "$have" = "$subnet $range" ] || {
      echo "$name tồn tại với '$have' (cần '$subnet $range') — dừng; gỡ container khỏi network, docker network rm $name rồi chạy lại"
      exit 1; }
    echo "giữ   $name $subnet ip-range=$range"
  else
    flags=(); [ "$internal" = yes ] && flags+=(--internal); [ "$range" != - ] && flags+=(--ip-range "$range")
    docker network create "${flags[@]}" --subnet "$subnet" --label meshguard.role=platform "$name" >/dev/null
    echo "tạo   $name $subnet$([ "$internal" = yes ] && echo ' (internal)') ip-range=$range"
  fi
done <<< "$NETS"
