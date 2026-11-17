#!/usr/bin/env bash
# Isolation suite v1 (P2-T15) trên Headscale thật: IT-06 (apply policy cho A ⇒ sha256 GetPolicy của B không đổi), IT-10
# (API key của A bị instance B trả 401) và IT-20 (lỗi registry giữa A và B ⇒ mọi lời gọi qua ForTenant thất bại, không
# dữ liệu nào của tenant kia) — qua Registry.ForTenant và đúng khối listener admin của edge; IT-20 chạy cả ở mức target
# và trên Locator thật của P2-T11 (registry trong PostgreSQL + SecretStore, lỗi tiêm vào chính các hàng).
#
#   bash tests/isolation/headscale/run.sh                    # docker không cần sudo (runner GitHub)
#   DOCKER="sudo docker" HSISO_PREFIX=p2t15-hsiso bash ...   # VM build (docker cần sudo, tiền tố tài nguyên riêng)
#   HSISO_HS_IMAGE=<ref> bash ...                            # image Headscale được thử (mặc định: xem dưới)
#
# Dùng lại các mảnh của harness contract P2-T10 (tests/integration/headscale/run.sh): mọi image pin theo digest trong
# versions.lock, config Headscale render bằng tools/render_instance.py (chỉ ghi đè server_url bằng
# HEADSCALE_SERVER_URL vì mạng thử không có TLS), container chạy như compose của tenant (UID riêng, rootfs chỉ đọc,
# cap_drop ALL, no-new-privileges), edge = Caddy chạy ĐÚNG khối listener admin trích từ
# infrastructure/caddy/Caddyfile.tmpl. Khác contract: HAI instance (A, B — testdata/params-{a,b}.json), mỗi instance
# một network /29 riêng (internal) chỉ có nó và edge, data trên tmpfs; binary test build từ module chính
# (./tests/isolation/headscale) trong [images.golang]; PostgreSQL [images.postgres] trên network admin giữ registry thật
# cho Locator (IT-20). Headscale = image tenant chạy: HSISO_HS_IMAGE nếu có, nếu không thì [images.mg-headscale] (bản
# vá P2-T10a) khi đã pin, chưa pin thì [images.headscale] (như tools/render_instance.py và harness E2E). API key của
# từng instance, token của listener admin và mật khẩu superuser PostgreSQL sinh mới mỗi lần chạy, nằm trong thư mục tạm
# 0700, không in ra. Mọi container/network mang tiền tố $HSISO_PREFIX và bị xóa khi thoát (giữ hai volume cache Go
# <prefix>-gomod, <prefix>-gocache; HSISO_KEEP_CACHE=0 để xóa).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/tests/isolation/headscale"
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${HSISO_PREFIX:-hsiso}
ADMIN_CIDR=${HSISO_ADMIN_CIDR:-10.249.253.0/29}
EDGE_IP=${HSISO_EDGE_IP:-10.249.253.2}
ADMIN_PORT=8081
KEEP_CACHE=${HSISO_KEEP_CACHE:-1}
OUT=${HSISO_OUT:-$(mktemp -d -t hsiso-out.XXXXXX)}
mkdir -p "$OUT"
WORK=$(mktemp -d -t hsiso-work.XXXXXX)
chmod 0711 "$WORK"
log() { printf '[hsiso %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

lock() {  # <image name in versions.lock> → image@index ("" khi chưa có hoặc chưa pin digest)
  python3 - "$ROOT/versions.lock" "$1" <<'PY'
import re, sys, tomllib
img = tomllib.load(open(sys.argv[1], "rb"))["images"].get(sys.argv[2], {})
print(f"{img['image']}@{img['index']}" if re.fullmatch(r"sha256:[0-9a-f]{64}", str(img.get("index", ""))) else "")
PY
}
CADDY_IMAGE=$(lock caddy); GO_IMAGE=$(lock golang); ALPINE_IMAGE=$(lock alpine); PG_IMAGE=$(lock postgres)
HS_IMAGE=${HSISO_HS_IMAGE:-$(lock mg-headscale)}
[ -n "$HS_IMAGE" ] || HS_IMAGE=$(lock headscale)

param() {  # <params file> <key>
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

cleanup() {
  local rc=$?
  set +e
  for c in "$P-edge" "$P-hs-a" "$P-hs-b" "$P-run" "$P-pg"; do d rm -f "$c" >/dev/null 2>&1; done
  for n in "$P-tenant-a" "$P-tenant-b" "$P-admin"; do d network rm "$n" >/dev/null 2>&1; done
  [ "$KEEP_CACHE" = 1 ] || d volume rm -f "$P-gomod" "$P-gocache" >/dev/null 2>&1
  rm -rf "$WORK"
  log "kết quả trong $OUT (exit $rc)"
  exit $rc
}
trap cleanup EXIT

mkdir -m 0700 "$WORK/secrets" "$WORK/bin" "$WORK/edge"
( umask 077; head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40 > "$WORK/secrets/edge_token" )
[ "$(wc -c < "$WORK/secrets/edge_token")" -eq 40 ] || { echo "token edge không đủ 40 ký tự"; exit 2; }

# ---------------------------------------------------------------- khối listener admin của edge (nguyên văn template)
python3 - "$ROOT/infrastructure/caddy/Caddyfile.tmpl" "$WORK/edge/Caddyfile" "$ADMIN_PORT" "$EDGE_IP" "$ADMIN_CIDR" <<'PY'
import string, sys
tmpl, out, port, ip, cidr = sys.argv[1:6]
text = open(tmpl, encoding="utf-8").read()
start = text.index("http://:${admin_port} {")
end = text.index("\n}\n", start) + 3
block = string.Template(text[start:end]).substitute(admin_port=port, edge_admin_ip=ip, admin_subnet=cidr)
for must in ("header_up -X-MG-Token", "header_up -X-MG-Instance", "{file./run/secrets/admin_token}", "path('/api/v1/*')"):
    assert must in block, must
block = block.replace("\timport internal_log\n", "")
open(out, "w", encoding="utf-8").write("{\n\tadmin off\n\tpersist_config off\n\tauto_https off\n}\n\n" + block)
PY

# ---------------------------------------------------------------- binary test (module chính)
log "build binary test (go vet + go test -c) trong $GO_IMAGE"
d volume create "$P-gomod" >/dev/null
d volume create "$P-gocache" >/dev/null
d run --rm -v "$ROOT:/src:ro" -v "$P-gomod:/go/pkg/mod" -v "$P-gocache:/root/.cache/go-build" -v "$WORK/bin:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 -w /src "$GO_IMAGE" \
  sh -c "go vet ./tests/isolation/headscale/ && go test -c -o /out/hsiso.test ./tests/isolation/headscale/ && chown $(id -u):$(id -g) /out/hsiso.test"

# ---------------------------------------------------------------- hai instance + edge
d network create --internal --subnet "$ADMIN_CIDR" "$P-admin" >/dev/null
for x in a b; do
  PARAMS="$HERE/testdata/params-$x.json"
  SLUG=$(param "$PARAMS" slug); NET=$(param "$PARAMS" net_cidr); UID_=$(param "$PARAMS" run_uid)
  python3 "$ROOT/tools/render_instance.py" "$PARAMS" "$WORK/render-$x" >/dev/null
  chmod -R a+rX "$WORK/render-$x"
  d network create --internal --subnet "$NET" "$P-tenant-$x" >/dev/null
  log "Headscale $x ($SLUG, $NET, UID $UID_) — $HS_IMAGE"
  d run -d --name "$P-hs-$x" --network "$P-tenant-$x" --network-alias "hs-$SLUG" \
    --user "$UID_:$UID_" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs "/var/run/headscale:size=1m,mode=0700,uid=$UID_,gid=$UID_" \
    --tmpfs "/var/lib/headscale:size=32m,mode=0700,uid=$UID_,gid=$UID_" \
    -v "$WORK/render-$x/config:/etc/headscale:ro" -v "$WORK/render-$x/records:/etc/headscale-records:ro" \
    -e "HEADSCALE_SERVER_URL=http://hs-$SLUG:8080" "$HS_IMAGE" serve >/dev/null
done
for x in a b; do
  ok=0
  for _ in $(seq 1 60); do
    if d exec "$P-hs-$x" headscale health >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ $ok = 1 ] || { d logs --tail 50 "$P-hs-$x"; echo "Headscale $x không healthy sau 60 s"; exit 1; }
  log "Headscale $x: $(d exec "$P-hs-$x" headscale version -o json \
    | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["version"], "commit", v["commit"])')"
  ( umask 077; d exec "$P-hs-$x" headscale apikeys create --expiration 3h -o json \
      | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))' > "$WORK/secrets/api_key_$x" )
done

log "edge $CADDY_IMAGE — listener admin $EDGE_IP:$ADMIN_PORT, nối vào network của A và của B"
d run -d --name "$P-edge" --network "$P-admin" --ip "$EDGE_IP" \
  -v "$WORK/edge/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$WORK/secrets/edge_token:/run/secrets/admin_token:ro" \
  "$CADDY_IMAGE" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
d network connect "$P-tenant-a" "$P-edge"
d network connect "$P-tenant-b" "$P-edge"
sleep 2
[ "$(d inspect -f '{{.State.Running}}' "$P-edge")" = true ] || { d logs "$P-edge"; exit 1; }

# ---------------------------------------------------------------- PostgreSQL của registry (IT-20 trên Locator thật)
# Mật khẩu superuser một lần, chỉ trong hai env-file 0600 (server, test) — như harness contract.
log "PostgreSQL $PG_IMAGE (registry cho Locator thật)"
( umask 077
  PGPW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf 'POSTGRES_PASSWORD=%s\n' "$PGPW" > "$WORK/secrets/pg-server.env"
  printf 'MG_TEST_PG_ADMIN_URL=postgres://postgres:%s@%s-pg:5432/postgres?sslmode=disable\nMG_TEST_PG_REQUIRED=1\n' "$PGPW" "$P" \
    > "$WORK/secrets/pg.env" )
d run -d --name "$P-pg" --network "$P-admin" --env-file "$WORK/secrets/pg-server.env" "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  d exec "$P-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
  sleep 1
done
d exec "$P-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null || { d logs --tail 30 "$P-pg"; exit 1; }

# ---------------------------------------------------------------- test (chỉ trên network admin: như api/worker)
log "chạy IT-06, IT-10, IT-20 (mức target và Locator thật)"
d create --name "$P-run" --network "$P-admin" --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$WORK/bin:/hsiso:ro" -v "$WORK/secrets:/secrets:ro" --env-file "$WORK/secrets/pg.env" \
  -e "MG_HSISO_ADMIN_URL=http://$EDGE_IP:$ADMIN_PORT" -e MG_HSISO_SECRETS_DIR=/secrets \
  -e "MG_HSISO_SLUG_A=$(param "$HERE/testdata/params-a.json" slug)" \
  -e "MG_HSISO_SLUG_B=$(param "$HERE/testdata/params-b.json" slug)" \
  "$ALPINE_IMAGE" /hsiso/hsiso.test -test.v -test.count=1 -test.timeout=10m >/dev/null
set +e
d start -a "$P-run" > "$OUT/isolation.log" 2>&1
rc=$?
set -e
grep -E '^(\s*--- (PASS|FAIL|SKIP)|PASS|FAIL|ok)|isolation_test.go:' "$OUT/isolation.log" || true
if [ $rc -ne 0 ]; then tail -40 "$OUT/isolation.log"; log "ISOLATION (Headscale): FAIL"; exit $rc; fi
log "ISOLATION (Headscale): PASS"
