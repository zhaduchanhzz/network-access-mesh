#!/bin/bash
# Edge conformance trên host staging (P1-T10a, §14.6). Chạy lại mỗi khi infrastructure/caddy/** đổi.
#   sudo bash run_staging.sh <mesh_domain> <public_entry_ipv4> [tenant_slug ...]
# - Dựng network tenant giả mg-t-conf-echo (/29 cuối pool, internal) + container giữ netns có alias hs-conf-echo,
#   chạy echo_upstream.py trong netns đó (nsenter -n: tiến trình của host, chỉ mượn network namespace), gắn edge
#   vào network này lúc chạy (không reload).
# - Container giữ netns trên mg-edge (vai trò client của site public), mg-admin (api/worker), mg-obs (Prometheus):
#   conformance.py chạy trong netns của từng container.
# - Với tenant thật đầu tiên: tạo API key hạn 1 giờ bằng CLI, giữ trong file tmpfs chỉ root đọc được, thử qua listener
#   admin (phải 200) và listener public (phải 404), rồi expire key. Key không bao giờ được in ra.
# - Cuối cùng dừng tenant giả (tenant "đang dừng" phải trả 404) và gỡ mọi thứ; log của echo bị xóa (nếu edge lỡ
#   không gỡ token, log chứa token thật).
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
DOMAIN=${1:?usage: run_staging.sh <mesh_domain> <public_entry_ipv4> [tenant ...]}; ENTRY=${2:?public entry ip}; shift 2
TENANTS=$(IFS=,; echo "$*")
ECHO=conf-echo; NET=mg-t-$ECHO; SUBNET=10.250.255.240/29
IMG=docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
SEC=/opt/meshguard/secrets
LOG=$(mktemp /tmp/mg-echo.XXXXXX.jsonl); KEYF=""
ECHO_PID=""

cleanup() {
  [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
  [ -n "$KEYF" ] && rm -f "$KEYF"
  docker network disconnect "$NET" mg-edge >/dev/null 2>&1 || true
  docker rm -f mg-test-echo mg-test-admin mg-test-obs mg-test-public >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$LOG"
}
trap cleanup EXIT

holder() {   # <name> <network> [alias] → PID of the holder (netns owner)
  docker run -d --name "$1" --network "$2" ${3:+--network-alias "$3"} --user 65534:65534 --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true --label meshguard.role=test "$IMG" sleep 3600 >/dev/null
  docker inspect -f '{{.State.Pid}}' "$1"
}
rc=0
run() { local pid=$1; shift; nsenter -t "$pid" -n python3 -I "$DIR/conformance.py" "$@" || rc=1; }

docker network create --internal --subnet "$SUBNET" --label meshguard.role=test "$NET" >/dev/null
EP=$(holder mg-test-echo "$NET" "hs-$ECHO")
nsenter -t "$EP" -n python3 -I "$DIR/echo_upstream.py" "$LOG" & ECHO_PID=$!
docker network connect "$NET" mg-edge
EDGE_TNET=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" mg-edge)
PP=$(holder mg-test-public mg-edge); AP=$(holder mg-test-admin mg-admin); OP=$(holder mg-test-obs mg-obs)
sleep 1
echo "== edge on $NET: $EDGE_TNET; echo upstream pid $ECHO_PID"

run "$PP" public --edge 10.249.0.2 --mesh-domain "$DOMAIN" --echo "$ECHO" --entry-ip "$ENTRY" --tenants "$TENANTS" --log "$LOG"
run "$AP" admin --edge 10.249.2.2:8081 --token-file "$SEC/app/edge_admin_token" \
  --other-token-file "$SEC/obs/edge_metrics_token" --echo "$ECHO" --log "$LOG"
run "$OP" metrics --edge 10.249.3.2:9091 --token-file "$SEC/obs/edge_metrics_token" \
  --other-token-file "$SEC/app/edge_admin_token" --echo "$ECHO" --log "$LOG"
echo "== internal listeners from a container on mg-edge only (future web/api/idp)"
run "$PP" unreachable --targets 10.249.2.2:8081,10.249.3.2:9091
echo "== every edge listener from inside a tenant network (edge IP on that network and the listener IPs)"
run "$EP" unreachable --targets "$EDGE_TNET:80,$EDGE_TNET:443,$EDGE_TNET:8080,$EDGE_TNET:8081,$EDGE_TNET:8443,$EDGE_TNET:9091,10.249.0.2:443,10.249.0.2:8080,10.249.0.2:8443,10.249.2.2:8081,10.249.3.2:9091"

# Tunnel-facing listener (P1-T17, template_version ≥ 3): only the VPS end of the tunnel may connect, with a PROXY
# header (V-17). From a container on mg-edge and from the host itself (source ≠ tunnel peer) nothing may answer —
# neither without a header nor with a forged one.
TUN=$(docker port mg-edge 8443/tcp 2>/dev/null | head -1 | cut -d: -f1)
if [ -n "$TUN" ]; then
  echo "== tunnel-facing listener ($TUN:8080/8443 → 10.249.0.2) from non-peer sources"
  run "$PP" tunnel-reject --targets 10.249.0.2:8443,10.249.0.2:8080 --sni "$ECHO.$DOMAIN"
  python3 -I "$DIR/conformance.py" tunnel-reject --targets "$TUN:8443,$TUN:8080" --sni "$ECHO.$DOMAIN" || rc=1
else
  echo "== no tunnel-facing listener published (template_version < 3 or Local Development only)"
fi

if [ -n "$TENANTS" ]; then
  T=${TENANTS%%,*}
  echo "== real API key of $T (1 h, expired right after)"
  before=$(docker exec "mg-hs-$T" headscale apikeys list -o json | python3 -c 'import json,sys; print(" ".join(k["prefix"] for k in (json.load(sys.stdin) or [])))')
  KEYF=$(mktemp /dev/shm/mg-key.XXXXXX)
  docker exec "mg-hs-$T" headscale apikeys create --expiration 1h -o json | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))' > "$KEYF"
  run "$AP" real-api --via admin --edge 10.249.2.2:8081 --key-file "$KEYF" --instance "$T" --token-file "$SEC/app/edge_admin_token"
  run "$PP" real-api --via public --edge 10.249.0.2 --key-file "$KEYF" --instance "$T" --mesh-domain "$DOMAIN"
  rm -f "$KEYF"; KEYF=""
  for p in $(docker exec "mg-hs-$T" headscale apikeys list -o json | python3 -c 'import json,sys
before = set(sys.argv[1].split())
print(" ".join(k["prefix"] for k in (json.load(sys.stdin) or []) if k["prefix"] not in before))' "$before"); do
    docker exec "mg-hs-$T" headscale apikeys expire --prefix "$p" >/dev/null && echo "  expired API key prefix $p"
  done
fi

echo "== tenant stopped"
kill "$ECHO_PID" 2>/dev/null || true; ECHO_PID=""
docker stop -t 1 mg-test-echo >/dev/null
run "$PP" stopped --edge 10.249.0.2 --mesh-domain "$DOMAIN" --slug "$ECHO"

[ "$rc" = 0 ] && echo "EDGE CONFORMANCE: PASS" || echo "EDGE CONFORMANCE: FAIL"
exit "$rc"
