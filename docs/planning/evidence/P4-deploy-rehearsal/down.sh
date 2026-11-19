#!/bin/bash
# dep4 — dọn sạch diễn tập trên VM 110 (chỉ tài nguyên mang tên/nhãn dep4; không prune toàn cục).
set -uo pipefail
O="sudo -n docker"
bash "$HOME/dep4/outer.sh" down
$O stop -t 20 dep4-host >/dev/null 2>&1; $O rm -f dep4-host >/dev/null 2>&1
for n in dep4-lan dep4-tun dep4-inet; do $O network rm "$n" >/dev/null 2>&1; done
$O image rm dep4-host:skel >/dev/null 2>&1
$O image rm docker.io/library/haproxy@sha256:b9fe316f718d5015c5cfebd8ca019591f3e44656f61d93cb8b59a1028961e530 >/dev/null 2>&1  # chỉ nếu do diễn tập kéo về
sudo -n rm -rf "$HOME/dep4"      # gồm /var/lib/docker của host lồng, CA thử, mật khẩu/TOTP thử, identity khôi phục thử
echo "còn: $($O ps -aq --filter label=dep4=1 | wc -l) container, $($O network ls -q --filter label=dep4=1 | wc -l) network"
