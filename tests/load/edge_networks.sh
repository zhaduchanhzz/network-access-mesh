#!/bin/bash
# P1-T20 (V-33): edge với N network tenant giả. Chạy trên host staging (root).
#   sudo bash edge_networks.sh grow <N>      # tạo network/holder giả tới đủ N (fk-0000 … fk-N-1) và gắn edge vào
#   sudo bash edge_networks.sh measure <N>   # DNS trong netns edge, restart edge, recreate edge + gắn lại
#   sudo bash edge_networks.sh cleanup       # gỡ edge khỏi mọi network giả (đo thời gian gỡ), xóa holder và network
# Mỗi network giả: internal, subnet /29 tường minh trong 10.250.1.0–10.250.15.255 (không chồng A/B), một container
# alpine (đã pin) đứng yên mang alias hs-fk-NNNN. In thời gian từng bước; không đụng dữ liệu của tenant thật.
set -euo pipefail
# Tham số môi trường (domain, IP LAN) từ env file — tools/mgenv.py; ghi đè bằng MG_ENV_FILE
ENV_FILE=${MG_ENV_FILE:-$(dirname "$0")/../../infrastructure/environments/staging/staging.env}
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
: "${MG_BASE_DOMAIN:?}" "${MG_LAN_IPV4:?}"
IMG=docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
EDGE=mg-edge
COMPOSE=/opt/meshguard/core/compose.edge.yaml
REATTACH=${REATTACH:-/home/mgdeploy/mg/infrastructure/host/reattach-edge.sh}
ms() { date +%s%3N; }
name() { printf 'fk-%04d' "$1"; }
subnet() { echo "10.250.$((1 + $1 / 32)).$(( ($1 % 32) * 8 ))/29"; }
stats() { python3 -c 'import statistics,sys; v=sorted(float(x) for x in sys.stdin.read().split()); n=len(v)
print("n=%d p50=%.0fms p95=%.0fms max=%.0fms total=%.1fs" % (n, statistics.median(v), v[max(0,int(n*.95)-1)], v[-1], sum(v)/1000) if v else "n=0")'; }
edge_nets() { docker inspect -f '{{len .NetworkSettings.Networks}}' "$EDGE"; }
client_streams() { local p; p=$(docker inspect -f '{{.State.Pid}}' "$EDGE")
  nsenter -t "$p" -n ss -Htn state established "( sport = :443 )" | awk '{print $4}' | grep -E '^192\.168\.1\.(21|22|17):' | sort | xargs; }
wait_healthy() { local t0; t0=$(ms); for _ in $(seq 1 600); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$EDGE" 2>/dev/null)" = healthy ] && { echo $(( $(ms) - t0 )); return; }; sleep 0.2; done; echo timeout; }
wait_key200() { local t0; t0=$(ms); for _ in $(seq 1 600); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 --resolve "tenant-a.mesh.$MG_BASE_DOMAIN:443:$MG_LAN_IPV4" "https://tenant-a.mesh.$MG_BASE_DOMAIN/key?v=113")" = 200 ] && { echo $(( $(ms) - t0 )); return; }; sleep 0.2; done; echo timeout; }

grow() {
  local n=$1 i created=0 t0 times=""
  t0=$(ms)
  for i in $(seq 0 $((n - 1))); do
    local nm; nm=$(name "$i")
    docker network inspect "mg-t-$nm" >/dev/null 2>&1 && continue
    docker network create --internal --subnet "$(subnet "$i")" --label meshguard.role=test "mg-t-$nm" >/dev/null
    docker run -d --name "mg-hs-$nm" --network "mg-t-$nm" --network-alias "hs-$nm" --user 65534:65534 --read-only \
      --cap-drop ALL --memory 16m --label meshguard.role=test "$IMG" sleep infinity >/dev/null
    created=$((created + 1))
  done
  echo "created $created fake networks+holders in $(( ($(ms) - t0) / 1000 )) s"
  local before; before=$(client_streams)
  for i in $(seq 0 $((n - 1))); do
    local nm s; nm=$(name "$i")
    docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "mg-t-$nm" | grep -qw "$EDGE" && continue
    s=$(ms); docker network connect "mg-t-$nm" "$EDGE"; times+="$(( $(ms) - s )) "
  done
  echo "attach (new networks): $(echo "$times" | stats)"
  local after; after=$(client_streams)
  echo "edge networks now: $(edge_nets); client streams before/after attach: $(echo "$before" | wc -w)/$(echo "$after" | wc -w); identical 4-tuples: $([ "$before" = "$after" ] && echo yes || echo NO)"
  docker stats --no-stream --format '{{.Name}} mem={{.MemUsage}} cpu={{.CPUPerc}}' "$EDGE" mg-hs-tenant-a
}

measure() {
  local n=$1 p q
  p=$(docker inspect -f '{{.State.Pid}}' "$EDGE")
  for q in hs-fk-0000. "hs-$(name $((n / 2)))." "hs-$(name $((n - 1)))." hs-tenant-a. hs-nonexistent-zz.; do
    printf '  dns %-22s ' "$q"
    for _ in 1 2 3 4 5; do nsenter -t "$p" -n dig +time=2 +tries=1 @127.0.0.11 "$q" A | awk '/Query time/{printf "%sms ", $4}'; done; echo
  done
  echo "--- restart edge (networks kept by Docker)"
  local s; s=$(ms); docker restart -t 30 "$EDGE" >/dev/null; echo "  docker restart returned after $(( $(ms) - s )) ms"
  echo "  healthy after +$(wait_healthy) ms; tenant-a /key 200 after +$(wait_key200) ms; total $(( $(ms) - s )) ms; edge networks: $(edge_nets)"
  echo "--- recreate edge (runtime networks lost) + reattach"
  s=$(ms); docker compose -f "$COMPOSE" up -d --force-recreate >/dev/null 2>&1; echo "  compose recreate returned after $(( $(ms) - s )) ms; healthy after +$(wait_healthy) ms; edge networks: $(edge_nets)"
  local r; r=$(ms); bash "$REATTACH" >/dev/null; local times="" i nm t
  for i in $(seq 0 $((n - 1))); do nm=$(name "$i"); t=$(ms); docker network connect "mg-t-$nm" "$EDGE"; times+="$(( $(ms) - t )) "; done
  echo "  reattach A/B + $n fake: $(( ($(ms) - r) )) ms (fake: $(echo "$times" | stats)); total recreate→all attached $(( $(ms) - s )) ms; edge networks: $(edge_nets)"
  echo "  tenant-a /key 200 after +$(wait_key200) ms"
}

cleanup() {
  local times="" nm t
  for nm in $(docker network ls --filter label=meshguard.role=test --format '{{.Name}}' | grep '^mg-t-fk-' | sort); do
    if docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$nm" | grep -qw "$EDGE"; then
      t=$(ms); docker network disconnect "$nm" "$EDGE"; times+="$(( $(ms) - t )) "
    fi
  done
  echo "detach: $(echo "$times" | stats)"
  docker ps -aq --filter label=meshguard.role=test --filter name=mg-hs-fk- | xargs -r docker rm -f >/dev/null
  docker network ls --filter label=meshguard.role=test --format '{{.Name}}' | grep '^mg-t-fk-' | xargs -r docker network rm >/dev/null
  echo "cleanup done; edge networks: $(edge_nets)"
}

case "${1:-}" in
  grow) grow "${2:?N}" ;;
  measure) measure "${2:?N}" ;;
  cleanup) cleanup ;;
  *) echo "usage: edge_networks.sh grow <N> | measure <N> | cleanup"; exit 2 ;;
esac
