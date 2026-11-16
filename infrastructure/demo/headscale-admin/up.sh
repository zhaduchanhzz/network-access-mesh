#!/bin/bash
# Dựng demo headscale-admin trên host staging (chạy bằng sudo). Không in secret nào.
#   panel  : mg-demo-panel — headscale-admin 1.3.0 build từ commit 0a4ca5e; chỉ ở network internal mg-demo-int
#            (không ra Internet, không Docker socket, không publish cổng); xem qua SSH tunnel tới 10.249.250.3:3000
#   proxy  : mg-demo-proxy — image edge của dự án (Caddy); mg-demo-int + mg-admin; gắn token nội bộ, ghim tenant-c
#   tenant : tenant-c (tenant demo riêng — A/B không bị đụng tới); API key của panel hạn 168 giờ
set -euo pipefail
SRC=${1:?usage: up.sh <dir with Caddyfile>}
D=/opt/meshguard/demo/r2
EDGE_IMG=$(docker inspect -f '{{.Config.Image}}' mg-edge)
PANEL_IMG=headscale-admin:1.3.0-0a4ca5e
install -d -m 0700 -o root -g root /opt/meshguard/demo "$D"
install -m 0644 -o root -g root "$SRC/Caddyfile" "$D/Caddyfile"
# token nội bộ của listener admin: bản sao cho proxy (non-root 10001), xóa khi gỡ demo
install -m 0440 -o root -g 10001 /opt/meshguard/secrets/app/edge_admin_token "$D/admin_token"
if [ ! -s "$D/panel.env" ]; then
  umask 077
  key=$(docker exec mg-hs-tenant-c headscale apikeys create --expiration 168h -o json |
        python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))')
  case "$key" in hskey-api-*) ;; *) echo "không tạo được API key"; exit 1 ;; esac
  printf 'PANEL_MASTER_KEY=%s\nPANEL_SESSION_SECRET=%s\nHS_API_KEY=%s\n' \
    "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$key" > "$D/panel.env"
  unset key
  echo "panel.env: 3 secret mới (master key, session secret, API key tenant-c hạn 168h)"
fi
docker network inspect mg-demo-int >/dev/null 2>&1 ||
  docker network create --internal --subnet 10.249.250.0/24 --label meshguard.role=demo mg-demo-int >/dev/null
docker rm -f mg-demo-proxy mg-demo-panel >/dev/null 2>&1 || true
docker run -d --name mg-demo-proxy --restart unless-stopped --label meshguard.role=demo \
  --network mg-demo-int --ip 10.249.250.2 \
  --user 10001:10001 --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true --read-only \
  --tmpfs /data:size=8m,uid=10001 --tmpfs /config:size=8m,uid=10001 --pids-limit 64 --memory 128m \
  -v "$D/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$D/admin_token:/run/secrets/admin_token:ro" \
  "$EDGE_IMG" >/dev/null
docker network connect mg-admin mg-demo-proxy
docker run -d --name mg-demo-panel --restart unless-stopped --label meshguard.role=demo \
  --network mg-demo-int --ip 10.249.250.3 \
  --read-only --tmpfs /tmp:size=64m,mode=1777 --tmpfs /run:size=8m,mode=755 \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 --memory 512m --cpus 1 \
  --env-file "$D/panel.env" \
  -e NODE_ENV=production -e PANEL_HOST=0.0.0.0 -e PANEL_PORT=3000 -e PANEL_DATA_DIR=/data \
  -e PANEL_PUBLIC_URL=http://127.0.0.1:9080 -e HS_URL=http://10.249.250.2:9000 -e HS_TRANSPORT=rest \
  -e TZ=UTC -e LOG_LEVEL=info \
  -v mg-demo-panel-data:/data \
  "$PANEL_IMG" >/dev/null
echo "proxy: $(docker inspect -f '{{.State.Status}}' mg-demo-proxy) — networks: $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' mg-demo-proxy)"
echo "panel: $(docker inspect -f '{{.State.Status}}' mg-demo-panel) — networks: $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' mg-demo-panel)"
