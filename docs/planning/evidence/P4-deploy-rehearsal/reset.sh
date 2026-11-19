#!/bin/bash
# dep4 — xóa trạng thái nền tảng TRONG host lồng (container/volume/network của dockerd lồng, /opt/meshguard, ~/mg),
# giữ image đã build/nạp, cây nguồn và script. Chỉ chạy bên trong dep4-host.
set -uo pipefail
docker ps -aq | xargs -r docker rm -f >/dev/null
docker volume ls -q | xargs -r docker volume rm -f >/dev/null
docker network ls --format '{{.Name}}' | grep -vE '^(bridge|host|none)$' | xargs -r docker network rm >/dev/null
nft delete table inet mg_host 2>/dev/null; nft delete table bridge mg_bridge 2>/dev/null
umount /run/mg-key-ceremony 2>/dev/null; rm -rf /run/mg-key-ceremony /run/mg-restore
rm -rf /opt/meshguard /root/mg /root/mg.bak-* /root/compose.* /root/Caddyfile.* /tmp/edge /tmp/mg-* /tmp/render /tmp/agent
rm -rf /root/dep4x/creds /root/dep4x/env-dep4 /root/dep4x/*.log
echo "reset xong: $(docker ps -aq | wc -l) container, $(docker volume ls -q | wc -l) volume, $(docker images -q | wc -l) image"
