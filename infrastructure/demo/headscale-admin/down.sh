#!/bin/bash
# Gỡ bản demo headscale-admin khỏi host staging (chạy bằng sudo). Không đụng tenant A/B.
#   sudo bash down.sh               # gỡ panel, proxy, network, volume, secret của demo; expire API key của panel
#   sudo bash down.sh --with-tenant # thêm: xóa tenant demo tenant-c (XÓA dữ liệu và khóa của tenant-c)
# Máy VM 105 (lab-c1) vẫn còn Tailscale: trên máy đó chạy `sudo tailscale logout` rồi gỡ theo
# tests/lab/install_tailscale_client.sh (dòng "Hoàn tác").
set -euo pipefail
D=/opt/meshguard/demo/r2
docker rm -f mg-demo-panel mg-demo-proxy >/dev/null 2>&1 || true
docker volume rm mg-demo-panel-data >/dev/null 2>&1 || true
docker network rm mg-demo-int >/dev/null 2>&1 || true
if docker inspect mg-hs-tenant-c >/dev/null 2>&1; then
  # tenant-c chỉ dùng cho demo: mọi API key của nó là của panel
  for p in $(docker exec mg-hs-tenant-c headscale apikeys list -o json |
             python3 -c 'import json,sys; print(" ".join(k["prefix"] for k in (json.load(sys.stdin) or [])))'); do
    docker exec mg-hs-tenant-c headscale apikeys expire --prefix "$p" >/dev/null && echo "expired API key prefix ${p:0:14}…"
  done
fi
rm -rf "$D"
echo "demo removed (panel, proxy, mg-demo-int, mg-demo-panel-data, $D)"
if [ "${1:-}" = --with-tenant ]; then
  bash "$(dirname "$0")/../../host/tenant-remove.sh" tenant-c --i-understand-this-deletes-data
fi
