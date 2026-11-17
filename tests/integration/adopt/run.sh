#!/usr/bin/env bash
# End-to-end của `meshguard admin adopt-instance` (P2-T11) với Headscale v0.29.7 thật, qua ĐÚNG khối listener admin
# của infrastructure/caddy/Caddyfile.tmpl — dựng như tests/integration/headscale/run.sh (P2-T10).
#
#   bash tests/integration/adopt/run.sh                                     # docker không cần sudo
#   DOCKER="sudo -n docker" ADOPT_PREFIX=p2t11-adopt bash tests/integration/adopt/run.sh   # VM build
#
# Môi trường dùng-một-lần, mọi image pin theo digest trong versions.lock:
#   - Headscale [images.headscale], config + meta/instance.json do tools/render_instance.py render từ testdata/params.json
#     (meta MÔ PHỎNG đúng file trên host), chạy như compose của tenant (user run_uid, rootfs chỉ đọc, cap_drop ALL);
#   - edge: Caddy [images.caddy] chạy nguyên khối listener admin trích từ Caddyfile.tmpl (token 40 ký tự sinh mới);
#   - PostgreSQL [images.postgres]: cụm thử, mật khẩu superuser sinh mới, chỉ nằm trong thư mục tạm 0700;
#   - binary test của apps/api build trong [images.golang], chạy trong [images.alpine].
# Trình tự: hai key "Phase 1" (hạn 1h và 720h) tạo bằng CLI trong container → key MỚI `apikeys create -e 2160h -o json`
# được pipe THẲNG vào stdin của tiến trình test (không ghi file) → test chạy `admin adopt-instance` thật, kiểm qua
# Registry.ForTenant, key Phase 1 bị từ chối, chạy lại (xoay key), canary → runner tự kiểm bằng
# `headscale apikeys list -o json`: đúng MỘT key còn hạn và đó là key nền tảng đang giữ.
# Subnet mặc định khác của P2-T10 để hai harness chạy song song được trên cùng máy. Mọi container/network/volume mang
# tiền tố $ADOPT_PREFIX và bị xóa khi thoát (giữ cache Go <prefix>-gomod, <prefix>-gocache; ADOPT_KEEP_CACHE=0 để xóa).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/tests/integration/adopt"
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${ADOPT_PREFIX:-adopt}
ADMIN_CIDR=${ADOPT_ADMIN_CIDR:-10.249.254.16/29}
EDGE_IP=${ADOPT_EDGE_IP:-10.249.254.18}
ADMIN_PORT=8081
KEEP_CACHE=${ADOPT_KEEP_CACHE:-1}
OUT=${ADOPT_OUT:-$(mktemp -d -t adopt-out.XXXXXX)}
mkdir -p "$OUT"
WORK=$(mktemp -d -t adopt-work.XXXXXX)
chmod 0711 "$WORK"
log() { printf '[adopt %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

lock() {  # <image name in versions.lock> → image@index
  python3 - "$ROOT/versions.lock" "$1" <<'PY'
import sys, tomllib
img = tomllib.load(open(sys.argv[1], "rb"))["images"][sys.argv[2]]
print(f"{img['image']}@{img['index']}")
PY
}
HS_IMAGE=$(lock headscale); CADDY_IMAGE=$(lock caddy); GO_IMAGE=$(lock golang)
PG_IMAGE=$(lock postgres); ALPINE_IMAGE=$(lock alpine)

PARAMS="$HERE/testdata/params.json"
read -r SLUG NET_CIDR RUN_UID PARAM_IMAGE < <(python3 - "$PARAMS" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print(p["slug"], p["net_cidr"], p["run_uid"], p["image"])
PY
)
[ "$PARAM_IMAGE" = "$HS_IMAGE" ] || { echo "testdata/params.json image ($PARAM_IMAGE) khác versions.lock ($HS_IMAGE)"; exit 2; }

cleanup() {
  local rc=$?
  set +e
  for c in "$P-run" "$P-edge" "$P-hs" "$P-pg"; do d rm -f "$c" >/dev/null 2>&1; done
  for n in "$P-tenant" "$P-admin" "$P-data"; do d network rm "$n" >/dev/null 2>&1; done
  d volume rm -f "$P-hsdata" >/dev/null 2>&1
  [ "$KEEP_CACHE" = 1 ] || d volume rm -f "$P-gomod" "$P-gocache" >/dev/null 2>&1
  rm -rf "$WORK"
  log "kết quả trong $OUT (exit $rc)"
  exit $rc
}
trap cleanup EXIT

wait_healthy() {
  for _ in $(seq 1 60); do
    if d exec "$P-hs" headscale health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  d logs --tail 50 "$P-hs" || true
  echo "Headscale không healthy sau 60 s"; return 1
}

# ---------------------------------------------------------------- render + secrets (không in ra)
log "render instance bằng tools/render_instance.py (meta/instance.json mô phỏng file trên host)"
python3 "$ROOT/tools/render_instance.py" "$PARAMS" "$WORK/render" >/dev/null
chmod -R a+rX "$WORK/render"
mkdir -m 0700 "$WORK/secrets" "$WORK/state" "$WORK/bin" "$WORK/edge"
chmod 0777 "$WORK/state"
( umask 077; head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40 > "$WORK/secrets/edge_token" )
[ "$(wc -c < "$WORK/secrets/edge_token")" -eq 40 ] || { echo "token edge không đủ 40 ký tự"; exit 2; }
( umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/secrets/pgpw" )
# bản cho container postgres (entrypoint đọc file cả với uid 999): chỉ đọc, trong thư mục 0700 của runner
install -m 0444 "$WORK/secrets/pgpw" "$WORK/secrets/pgpw.pg"
( umask 077; printf 'MG_TEST_PG_ADMIN_URL=postgres://postgres:%s@%s-pg:5432/postgres?sslmode=disable\nMG_TEST_PG_REQUIRED=1\n' \
    "$(cat "$WORK/secrets/pgpw")" "$P" > "$WORK/secrets/test.env" )

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

# ---------------------------------------------------------------- build test binary
log "build binary test của apps/api (go vet + go test -c) trong $GO_IMAGE"
d volume create "$P-gomod" >/dev/null
d volume create "$P-gocache" >/dev/null
d run --rm -v "$ROOT:/src:ro" -v "$P-gomod:/go/pkg/mod" -v "$P-gocache:/root/.cache/go-build" -v "$WORK/bin:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 -w /src "$GO_IMAGE" \
  sh -c "go vet ./apps/api && go test -c -o /out/api.test ./apps/api && chown $(id -u):$(id -g) /out/api.test"

# ---------------------------------------------------------------- networks, PostgreSQL, Headscale, edge
log "network $P-tenant ($NET_CIDR), $P-admin ($ADMIN_CIDR), $P-data — đều internal"
d network create --internal --subnet "$NET_CIDR" "$P-tenant" >/dev/null
d network create --internal --subnet "$ADMIN_CIDR" "$P-admin" >/dev/null
d network create --internal "$P-data" >/dev/null

log "PostgreSQL $PG_IMAGE"
d run -d --name "$P-pg" --network "$P-data" -e POSTGRES_PASSWORD_FILE=/run/secrets/pgpw \
  -v "$WORK/secrets/pgpw.pg:/run/secrets/pgpw:ro" "$PG_IMAGE" >/dev/null
for _ in $(seq 1 90); do
  d exec "$P-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
  sleep 1
done

d volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt "o=size=32m,uid=$RUN_UID,gid=$RUN_UID,mode=0700" "$P-hsdata" >/dev/null
log "Headscale $HS_IMAGE"
d run -d --name "$P-hs" --network "$P-tenant" --network-alias "hs-$SLUG" \
  --user "$RUN_UID:$RUN_UID" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs "/var/run/headscale:size=1m,mode=0700,uid=$RUN_UID,gid=$RUN_UID" \
  -v "$WORK/render/config:/etc/headscale:ro" -v "$WORK/render/records:/etc/headscale-records:ro" \
  -v "$P-hsdata:/var/lib/headscale" -e "HEADSCALE_SERVER_URL=http://hs-$SLUG:8080" \
  "$HS_IMAGE" serve >/dev/null
wait_healthy

log "hai key Phase 1 (hạn 1h và 720h) — như key ngắn hạn của P1-T08 và một key cũ khác"
( umask 077
  d exec "$P-hs" headscale apikeys create --expiration 1h -o json \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))' > "$WORK/secrets/phase1_short"
  d exec "$P-hs" headscale apikeys create --expiration 720h -o json \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))' > "$WORK/secrets/phase1_long" )

log "edge $CADDY_IMAGE — listener admin $EDGE_IP:$ADMIN_PORT"
d run -d --name "$P-edge" --network "$P-admin" --ip "$EDGE_IP" \
  -v "$WORK/edge/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$WORK/secrets/edge_token:/run/secrets/admin_token:ro" \
  "$CADDY_IMAGE" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
d network connect "$P-tenant" "$P-edge"
sleep 2
[ "$(d inspect -f '{{.State.Running}}' "$P-edge")" = true ] || { d logs "$P-edge"; exit 1; }

# ---------------------------------------------------------------- the adoption
d create --name "$P-run" -i --network "$P-admin" --user "$(id -u):$(id -g)" -e HOME=/tmp \
  --env-file "$WORK/secrets/test.env" -e MG_TEST_ADOPT_E2E=1 \
  -e "ADOPT_E2E_ADMIN_URL=http://$EDGE_IP:$ADMIN_PORT" -e ADOPT_E2E_TOKEN_FILE=/secrets/edge_token \
  -e ADOPT_E2E_META=/meta/instance.json -e ADOPT_E2E_PHASE1_DIR=/secrets -e ADOPT_E2E_STATE_DIR=/state \
  -v "$WORK/bin:/t:ro" -v "$WORK/secrets:/secrets:ro" -v "$WORK/state:/state" -v "$WORK/render/meta:/meta:ro" \
  "$ALPINE_IMAGE" /t/api.test -test.v -test.count=1 -test.timeout=10m -test.run '^TestAdoptE2E$' >/dev/null
d network connect "$P-data" "$P-run"
log "key MỚI: docker exec … headscale apikeys create -e 2160h -o json | stdin của tiến trình test (không file)"
set +e
d exec "$P-hs" headscale apikeys create --expiration 2160h -o json | d start -a -i "$P-run" > "$OUT/e2e.log" 2>&1
rc=${PIPESTATUS[1]}
set -e
grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS|FAIL|ok|\s+adopt_e2e_test.go)' "$OUT/e2e.log" | grep -v '=== RUN' || true
if [ "$rc" -ne 0 ]; then tail -60 "$OUT/e2e.log"; log "test thất bại"; exit "$rc"; fi
grep -q -- '--- PASS: TestAdoptE2E' "$OUT/e2e.log" || { log "TestAdoptE2E không chạy (bị skip?)"; exit 1; }

# ---------------------------------------------------------------- check from inside the instance (CLI, no credential)
d exec "$P-hs" headscale apikeys list -o json > "$WORK/state/keys.json"
python3 - "$WORK/state/keys.json" "$WORK/state/platform_key_prefix" "$WORK/secrets" <<'PY' | tee "$OUT/check.txt"
import datetime, json, os, sys
keys = json.load(open(sys.argv[1]))
platform = open(sys.argv[2]).read().strip()
now = datetime.datetime.now(datetime.timezone.utc)
def exp(k):
    e = k.get("expiration")
    if not e:
        return None
    if isinstance(e, dict):  # protojson Timestamp as {seconds, nanos}
        return datetime.datetime.fromtimestamp(int(e.get("seconds", 0)), datetime.timezone.utc)
    return datetime.datetime.fromisoformat(e.replace("Z", "+00:00"))
def prefix(k):
    return k["prefix"].removeprefix("hskey-api-")[:12]
valid = [prefix(k) for k in keys if exp(k) is None or exp(k) > now]
phase1 = []
for name in sorted(os.listdir(sys.argv[3])):
    if name.startswith("phase1_"):
        phase1.append(open(os.path.join(sys.argv[3], name)).read().strip().removeprefix("hskey-api-")[:12])
print(f"{len(keys)} API key trên instance; còn hạn: {len(valid)}; key nền tảng (prefix công khai): {platform}")
assert valid == [platform], f"còn hạn {valid}, cần đúng [{platform}]"
for p in phase1:
    assert p not in valid, f"key Phase 1 {p} vẫn còn hạn"
print(f"key Phase 1 ({len(phase1)}) đã hết hạn: {', '.join(phase1)}")
PY
log "ADOPT E2E: PASS"
