#!/bin/bash
# P2-T05 — dựng IdP (compose mg-idp đã render) trên máy dev/CI rồi chạy tests/idp/login_test.py. KHÔNG chạy trên host
# staging/production. Mọi container/network/volume/image mang tiền tố $PREFIX; domain là tên thử, không có trong DNS
# công khai: client thử nối thẳng proxy TLS thử qua 127.0.0.1:$PORT nhưng vẫn dùng hostname cho SNI (--connect).
#
#   bash tests/idp/run_dev.sh up | test | down | all       (all = up + test + down, down chạy cả khi lỗi)
#
# Proxy TLS thử (Caddy pin digest, `tls internal`) đứng ở 10.249.0.2 trên network $PREFIX-edge — đúng IP tĩnh của edge
# trên mg-edge mà compose render ra cho KC_PROXY_TRUSTED_ADDRESSES — nên stack thử dùng nguyên giá trị của bản thật;
# ba network thử dùng cùng subnet với mg-edge / mg-egress / mg-idp-data (infrastructure/host/networks.sh).
# Biến: PREFIX (mặc định mgidptest), PORT (18443), DOMAIN (<PREFIX>.test), WORK (/tmp/<PREFIX>-idp). Cần sudo (docker,
# file secret thuộc root). Secret sinh mới mỗi lượt bằng infrastructure/idp/secrets.sh, không in ra, xóa khi down.
# NET_BASE (mặc định 10.249 = dải thật): hai /16 khác nhau cho hai stack thử chạy CÙNG LÚC trên một máy (Docker từ chối
# subnet chồng nhau). Khác mặc định thì proxy thử không còn là IP edge mà KC_PROXY_TRUSTED_ADDRESSES tin ⇒ Keycloak bỏ
# qua X-Forwarded-* (issuer vẫn đúng vì hostname cố định — F3 của P2-T05) và hai kiểm tra "proxy tin cậy" của `test`
# không áp dụng; dùng cho test Go (IdP driver P2-T05a), không cho login_test.py. Proxy mang alias auth.<DOMAIN> trên
# network edge, như alias của edge trên mg-edge (§14.3): container Go gắn vào network đó phân giải tên qua DNS của Docker.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX=${PREFIX:-mgidptest}
PORT=${PORT:-18443}
DOMAIN=${DOMAIN:-$PREFIX.test}
WORK=${WORK:-/tmp/$PREFIX-idp}
NET_BASE=${NET_BASE:-10.249}
[[ $NET_BASE =~ ^10\.(2[0-5][0-9]|1[0-9][0-9]|[1-9]?[0-9])$ ]] || { echo "NET_BASE phải có dạng 10.<0-255>"; exit 2; }
CADDY=docker.io/library/caddy@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0   # 2.11.9-alpine (versions.lock)
IMAGE=$PREFIX-idp:test
PROJECT=$PREFIX-idp
PROXY_IP=$NET_BASE.0.2        # mặc định = IP tĩnh của edge (tools/render_edge.py EDGE_IPS) = KC_PROXY_TRUSTED_ADDRESSES
UNTRUSTED_IP=$NET_BASE.0.200  # container thử KHÔNG phải proxy
NETS="$PREFIX-edge $NET_BASE.0.0/24 no $NET_BASE.0.128/25
$PREFIX-egress $NET_BASE.5.0/24 no -
$PREFIX-idp-data $NET_BASE.6.0/24 yes -"
D="sudo docker"
compose() {
  sudo env MGT_WORK="$WORK" MGT_PREFIX="$PREFIX" docker compose -p "$PROJECT" \
    -f "$WORK/core/compose.idp.yaml" -f "$ROOT/tests/idp/compose.idp.test.yaml" "$@"
}
say() { printf '\n=== %s\n' "$*"; }

up() {
  mkdir -p "$WORK/core" "$WORK/proxy"
  say "build image tối ưu ($IMAGE) từ infrastructure/docker/idp"
  t0=$(date +%s)
  $D build -q -t "$IMAGE" "$ROOT/infrastructure/docker/idp" >/dev/null
  IMAGE_ID=$($D image inspect -f '{{.Id}}' "$IMAGE")
  echo "image $IMAGE_ID — $(( $(date +%s) - t0 )) s"
  say "secret dạng file (infrastructure/idp/secrets.sh) — không in giá trị"
  sudo bash "$ROOT/infrastructure/idp/secrets.sh" "$WORK/secrets/idp"
  say "render (tools/render_idp.py, MG_BASE_DOMAIN=$DOMAIN)"
  MG_BASE_DOMAIN=$DOMAIN python3 "$ROOT/tools/render_idp.py" "$ROOT/infrastructure/environments/staging/staging.env" \
    "$WORK/core" --image "$IMAGE_ID"
  say "network thử"
  while read -r name subnet internal range; do
    flags=(); [ "$internal" = yes ] && flags+=(--internal); [ "$range" != - ] && flags+=(--ip-range "$range")
    $D network create "${flags[@]}" --subnet "$subnet" --label meshguard.role=test "$name" >/dev/null
    echo "tạo $name $subnet internal=$internal"
  done <<< "$NETS"
  say "proxy TLS thử $PREFIX-proxy ($PROXY_IP, publish 127.0.0.1:$PORT)"
  cat > "$WORK/proxy/Caddyfile" <<EOF
{
	admin off
	persist_config off
	local_certs
	skip_install_trust
	auto_https disable_redirects
}
auth.$DOMAIN:443 {
	tls internal
	reverse_proxy idp:8080
}
EOF
  $D run -d --name "$PREFIX-proxy" --network "$PREFIX-edge" --ip "$PROXY_IP" --network-alias "auth.$DOMAIN" \
    -p "127.0.0.1:$PORT:443" \
    --read-only --tmpfs /data --tmpfs /config --cap-drop ALL --security-opt no-new-privileges \
    -v "$WORK/proxy/Caddyfile:/etc/caddy/Caddyfile:ro" "$CADDY" >/dev/null
  say "docker compose up (idp-db, idp) — chờ healthy"
  t0=$(date +%s)
  compose up -d --wait --wait-timeout 420
  echo "healthy sau $(( $(date +%s) - t0 )) s"
  for _ in $(seq 1 30); do $D exec "$PREFIX-proxy" test -s /data/caddy/pki/authorities/local/root.crt && break; sleep 1; done
  $D exec "$PREFIX-proxy" cat /data/caddy/pki/authorities/local/root.crt > "$WORK/ca.crt"
}

probe() {   # <ip> <X-Forwarded-For giả>: client credentials sai gửi THẲNG tới idp:8080 (không qua proxy), in mã HTTP
  $D run --rm --network "$PREFIX-edge" --ip "$1" --entrypoint wget "$CADDY" -S -q -O /dev/null \
    --header "X-Forwarded-For: $2" --header "X-Forwarded-Proto: https" --header "X-Forwarded-Host: auth.$DOMAIN" \
    --post-data 'grant_type=client_credentials&client_id=mg-idp-driver&client_secret=wrong-on-purpose' \
    http://idp:8080/realms/platform/protocol/openid-connect/token 2>&1 | grep -m1 'HTTP/' || true
}

test_() {
  say "hardening thực tế của container"
  for svc in idp-db idp; do
    cid=$(compose ps -q "$svc")
    $D inspect -f '{{.Name}} image={{.Config.Image}} user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} security_opt={{.HostConfig.SecurityOpt}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} ports={{.HostConfig.PortBindings}} health={{.State.Health.Status}}' "$cid"
    names=$($D inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | cut -d= -f1 | sort | tr '\n' ' ')
    echo "  tên biến môi trường: $names"
    bad=$(echo "$names" | tr ' ' '\n' | grep -Ei 'PASSWORD|SECRET|TOKEN' | grep -v '_FILE$' || true)
    if [ -n "$bad" ]; then echo "FAIL $svc có biến môi trường mang secret: $bad"; exit 1; fi
    echo "PASS $svc: không biến môi trường nào mang secret"
    $D inspect -f '  network: {{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "$cid"
  done
  cid=$(compose ps -q idp)
  say "log Keycloak (import realm, admin khởi tạo, lỗi)"
  $D logs "$cid" 2>&1 | grep -oE '"message":"[^"]*(Realm .* imported|Created temporary admin|started in|Listening on|Import finished)[^"]*"' | sed 's/^"message"://' || true
  errs=$($D logs "$cid" 2>&1 | grep -c '"level":"ERROR"' || true)
  echo "số dòng log mức ERROR: $errs"
  say "cổng quản trị 9000 (chỉ trong network Docker) và cổng chính 8080"
  $D exec "$PREFIX-proxy" wget -q -O - http://idp:9000/health/ready; echo
  echo "metrics: $($D exec "$PREFIX-proxy" wget -q -O - http://idp:9000/metrics | grep -c '^[a-z]') dòng mẫu"
  echo "8080/metrics: $($D exec "$PREFIX-proxy" wget -S -q -O /dev/null http://idp:8080/metrics 2>&1 | grep -m1 'HTTP/' || true)"
  echo "idp-db từ network edge (phải KHÔNG tới được): $($D exec "$PREFIX-proxy" sh -c 'nc -z -w 3 idp-db 5432 && echo TỚI-ĐƯỢC || echo không tới được')"
  say "proxy tin cậy: X-Forwarded-* chỉ được tin từ $PROXY_IP (client credentials sai, gửi thẳng idp:8080)"
  echo "từ container proxy $PROXY_IP, XFF=203.0.113.77: $($D exec "$PREFIX-proxy" wget -S -q -O /dev/null \
    --header 'X-Forwarded-For: 203.0.113.77' --header 'X-Forwarded-Proto: https' --header "X-Forwarded-Host: auth.$DOMAIN" \
    --post-data 'grant_type=client_credentials&client_id=mg-idp-driver&client_secret=wrong-on-purpose' \
    http://idp:8080/realms/platform/protocol/openid-connect/token 2>&1 | grep -m1 'HTTP/' || true)"
  echo "từ $UNTRUSTED_IP (không phải proxy), XFF=203.0.113.99: $(probe "$UNTRUSTED_IP" 203.0.113.99)"
  say "tests/idp/login_test.py"
  rc=0
  python3 "$ROOT/tests/idp/login_test.py" --base-url "https://auth.$DOMAIN" --connect "127.0.0.1:$PORT" \
    --cafile "$WORK/ca.crt" --realms-dir "$WORK/core/idp/realms" \
    --admin-conf <(sudo cat "$WORK/secrets/idp/keycloak.conf") --report "$WORK/report.json" \
    --event-ip-present 203.0.113.77 --event-ip-absent 203.0.113.99 || rc=$?
  say "tài nguyên"
  $D stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}} MEM={{.MemUsage}} PIDS={{.PIDs}}' \
    "$(compose ps -q idp)" "$(compose ps -q idp-db)" "$PREFIX-proxy"
  return $rc
}

down() {
  say "gỡ stack thử $PREFIX"
  if [ -f "$WORK/core/compose.idp.yaml" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  ids=$($D ps -aq --filter "label=com.docker.compose.project=$PROJECT")
  [ -z "$ids" ] || $D rm -f $ids >/dev/null
  $D volume rm "${PROJECT}_idp-db-data" >/dev/null 2>&1 || true
  $D rm -f "$PREFIX-proxy" >/dev/null 2>&1 || true
  for n in "$PREFIX-edge" "$PREFIX-egress" "$PREFIX-idp-data"; do $D network rm "$n" >/dev/null 2>&1 || true; done
  $D image rm "$IMAGE" >/dev/null 2>&1 || true
  sudo rm -rf "$WORK"
  echo "còn lại: $($D ps -a --filter "name=$PREFIX" -q | wc -l) container, $($D network ls --filter "name=$PREFIX" -q | wc -l) network, $($D volume ls --filter "name=$PREFIX" -q | wc -l) volume"
}

case "${1:-}" in
  up) up ;;
  test) test_ ;;
  down) down ;;
  all) trap down EXIT; up; test_ ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
