#!/usr/bin/env bash
# Contract test của adapter Headscale (P2-T10, §13.4 quy tắc 4; bản vá V-26: P2-T10a) — chạy trên máy có Docker
# (VM build, runner GitHub).
#
#   bash tests/integration/headscale/run.sh                  # docker không cần sudo (runner GitHub)
#   DOCKER="sudo docker" HSCT_PREFIX=p2t09-hsct bash ...     # VM build (docker cần sudo, tiền tố tài nguyên riêng)
#   HSCT_HS_IMAGE=<ref|build> bash ...                       # image Headscale được thử (mặc định: xem dưới)
#
# Dựng một môi trường dùng-một-lần, mọi image pin theo digest trong versions.lock:
#   - Headscale ĐƯỢC THỬ = bản vá của MeshGuard (infrastructure/docker/headscale): HSCT_HS_IMAGE nếu có ("build" = build
#     từ cây hiện tại), nếu không thì [images.mg-headscale] khi đã pin, nếu chưa pin thì build từ cây hiện tại. Image
#     chính thức [images.headscale] tạo DB trước pha 1, chạy pha 6 (đối chứng âm V-26 + rollback). Config do
#     tools/render_instance.py render từ testdata/params.json (chỉ ghi đè server_url bằng biến môi trường
#     HEADSCALE_SERVER_URL=http://hs-<slug>:8080 vì mạng thử không có TLS), chạy như compose của tenant: user 30001,
#     rootfs chỉ đọc, cap_drop ALL, no-new-privileges; data trên volume tmpfs 32 MiB (để pha 4 làm đầy được); một
#     container "giữ volume" để dữ liệu sống qua các lần restart và đổi image;
#   - edge: Caddy [images.caddy] chạy ĐÚNG khối listener admin trích từ infrastructure/caddy/Caddyfile.tmpl;
#   - client chính thức [images.tailscale] (pha 2); binary test build trong [images.golang].
# API key của instance và token của listener admin sinh mới mỗi lần chạy, nằm trong thư mục tạm 0700, không in ra.
# Các pha (TestP1_ … TestP7_) và việc runner làm giữa các pha: xem doc.go. Kết quả: $HSCT_OUT/observations.jsonl,
# phase-<n>.log, headscale-crash.log. Mọi container/network/volume/image mang tiền tố $HSCT_PREFIX và bị xóa khi thoát
# (giữ lại hai volume cache Go <prefix>-gomod, <prefix>-gocache; HSCT_KEEP_CACHE=0 để xóa).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/tests/integration/headscale"
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${HSCT_PREFIX:-hsct}
ADMIN_CIDR=${HSCT_ADMIN_CIDR:-10.249.254.0/29}
EDGE_IP=${HSCT_EDGE_IP:-10.249.254.2}
ADMIN_PORT=8081
KEEP_CACHE=${HSCT_KEEP_CACHE:-1}
OUT=${HSCT_OUT:-$(mktemp -d -t hsct-out.XXXXXX)}
mkdir -p "$OUT"
WORK=$(mktemp -d -t hsct-work.XXXXXX)
chmod 0711 "$WORK"
log() { printf '[hsct %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

lock() {  # <image name in versions.lock> → image@index ("" khi chưa có hoặc chưa pin digest)
  python3 - "$ROOT/versions.lock" "$1" <<'PY'
import re, sys, tomllib
img = tomllib.load(open(sys.argv[1], "rb"))["images"].get(sys.argv[2], {})
print(f"{img['image']}@{img['index']}" if re.fullmatch(r"sha256:[0-9a-f]{64}", str(img.get("index", ""))) else "")
PY
}
HS_OFFICIAL=$(lock headscale); CADDY_IMAGE=$(lock caddy); GO_IMAGE=$(lock golang)
TS_IMAGE=$(lock tailscale); ALPINE_IMAGE=$(lock alpine)
OFFICIAL_COMMIT=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["sources"]["headscale"]["commit"])' \
  "$ROOT/versions.lock")
HS_IMAGE=${HSCT_HS_IMAGE:-$(lock mg-headscale)}
HS_BUILT=""

PARAMS="$HERE/testdata/params.json"
read -r SLUG NET_CIDR RUN_UID NODE_EXPIRY < <(python3 - "$PARAMS" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print(p["slug"], p["net_cidr"], p["run_uid"], p["node_expiry"])
PY
)

cleanup() {
  local rc=$?
  set +e
  for c in "$P-ts" "$P-edge" "$P-hs" "$P-hold" "$P-run"; do d rm -f "$c" >/dev/null 2>&1; done
  for n in "$P-tenant" "$P-admin"; do d network rm "$n" >/dev/null 2>&1; done
  d volume rm -f "$P-hsdata" >/dev/null 2>&1
  [ -z "$HS_BUILT" ] || d image rm "$HS_BUILT" >/dev/null 2>&1
  [ "$KEEP_CACHE" = 1 ] || d volume rm -f "$P-gomod" "$P-gocache" >/dev/null 2>&1
  rm -rf "$WORK"
  log "kết quả trong $OUT (exit $rc)"
  exit $rc
}
trap cleanup EXIT

obs() {  # <quirk> <case> <observed> — quan sát do runner ghi (trạng thái container, log)
  python3 - "$WORK/state/observations.jsonl" "$@" <<'PY'
import json, sys, datetime
path, quirk, case, observed = sys.argv[1:5]
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps({"quirk": quirk, "case": case, "test": "run.sh", "observed": observed,
                        "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                       ensure_ascii=False) + "\n")
PY
}

wait_healthy() {
  for _ in $(seq 1 60); do
    if d exec "$P-hs" headscale health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  d logs --tail 50 "$P-hs" || true
  echo "Headscale không healthy sau 60 s"; return 1
}

# ---------------------------------------------------------------- render + secrets
log "render instance bằng tools/render_instance.py"
python3 "$ROOT/tools/render_instance.py" "$PARAMS" "$WORK/render" >/dev/null
chmod -R a+rX "$WORK/render"
mkdir -m 0700 "$WORK/secrets" "$WORK/state" "$WORK/bin" "$WORK/edge"
( umask 077; head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40 > "$WORK/secrets/edge_token" )
[ "$(wc -c < "$WORK/secrets/edge_token")" -eq 40 ] || { echo "token edge không đủ 40 ký tự"; exit 2; }
CONFIG_SHA=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["config_sha256"])' "$WORK/render/meta/instance.json")

# Khối listener admin của edge, trích nguyên văn từ template thật (chỉ thay 3 tham số, bỏ dòng log nội bộ).
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
log "build binary contract test (go vet + go test -c) trong $GO_IMAGE"
d volume create "$P-gomod" >/dev/null
d volume create "$P-gocache" >/dev/null
d run --rm -v "$ROOT:/src:ro" -v "$P-gomod:/go/pkg/mod" -v "$P-gocache:/root/.cache/go-build" -v "$WORK/bin:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 -w /src/tests/integration/headscale "$GO_IMAGE" \
  sh -c "go vet ./... && go test -c -o /out/hsct.test . && chown $(id -u):$(id -g) /out/hsct.test"


# ---------------------------------------------------------------- image Headscale được thử (bản vá P2-T10a)
# Mặc định: [images.mg-headscale] nếu đã pin và mang đúng bộ bản vá của cây này (label patched-commit = ARG
# HEADSCALE_PATCHED_COMMIT của Dockerfile — commit đó là hàm của tarball + các bản vá); ngược lại build từ cây.
TREE_COMMIT=$(sed -n 's/^ARG HEADSCALE_PATCHED_COMMIT=\([0-9a-f]\{40\}\)$/\1/p' "$ROOT/infrastructure/docker/headscale/Dockerfile")
if [ -z "${HSCT_HS_IMAGE:-}" ] && [ -n "$HS_IMAGE" ]; then
  d image inspect "$HS_IMAGE" >/dev/null 2>&1 || d pull -q "$HS_IMAGE" >/dev/null
  pinned=$(d image inspect -f '{{index .Config.Labels "io.meshguard.headscale.patched-commit"}}' "$HS_IMAGE")
  if [ "$pinned" != "$TREE_COMMIT" ]; then
    log "[images.mg-headscale] mang bản vá $pinned, cây hiện tại $TREE_COMMIT ⇒ build từ cây"
    HS_IMAGE=build
  fi
fi
if [ -z "$HS_IMAGE" ] || [ "$HS_IMAGE" = build ]; then
  HS_BUILT="$P-headscale:local"
  log "build image Headscale vá từ infrastructure/docker/headscale → $HS_BUILT (gồm unit test của các package bị vá)"
  d build -q -t "$HS_BUILT" "$ROOT/infrastructure/docker/headscale" >/dev/null
  HS_IMAGE=$HS_BUILT
fi
d image inspect "$HS_IMAGE" >/dev/null 2>&1 || d pull -q "$HS_IMAGE" >/dev/null
d image inspect "$HS_OFFICIAL" >/dev/null 2>&1 || d pull -q "$HS_OFFICIAL" >/dev/null
EXPECT_COMMIT=$(d image inspect -f '{{index .Config.Labels "io.meshguard.headscale.patched-commit"}}' "$HS_IMAGE")
if [ "$HS_IMAGE" = "$HS_OFFICIAL" ] || ! [[ "$EXPECT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || [ "$EXPECT_COMMIT" = "$OFFICIAL_COMMIT" ]; then
  echo "image được thử ($HS_IMAGE) phải là bản vá của infrastructure/docker/headscale (label io.meshguard.headscale.patched-commit)"
  exit 2
fi

# ---------------------------------------------------------------- networks, Headscale, edge
log "network $P-tenant ($NET_CIDR, internal) và $P-admin ($ADMIN_CIDR, internal)"
d network create --internal --subnet "$NET_CIDR" "$P-tenant" >/dev/null
d network create --internal --subnet "$ADMIN_CIDR" "$P-admin" >/dev/null
d volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt "o=size=32m,uid=$RUN_UID,gid=$RUN_UID,mode=0700" "$P-hsdata" >/dev/null
d run -d --name "$P-hold" --network none --user "$RUN_UID:$RUN_UID" -v "$P-hsdata:/data" "$ALPINE_IMAGE" sleep 86400 >/dev/null

start_hs() {  # <image> — Headscale như compose của tenant, trên volume dữ liệu dùng chung
  d rm -f "$P-hs" >/dev/null 2>&1 || true
  d run -d --name "$P-hs" --network "$P-tenant" --network-alias "hs-$SLUG" \
    --user "$RUN_UID:$RUN_UID" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs "/var/run/headscale:size=1m,mode=0700,uid=$RUN_UID,gid=$RUN_UID" \
    -v "$WORK/render/config:/etc/headscale:ro" -v "$WORK/render/records:/etc/headscale-records:ro" \
    -v "$P-hsdata:/var/lib/headscale" -e "HEADSCALE_SERVER_URL=http://hs-$SLUG:8080" \
    "$1" serve >/dev/null
  wait_healthy
}

version_of() {  # "<version> commit <commit>" do binary trong container đang chạy báo
  d exec "$P-hs" headscale version -o json \
    | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["version"], "commit", v["commit"])'
}

db_version() {  # hàng database_versions (RT-10) của DB trên volume — chỉ gọi khi Headscale đã dừng
  rm -rf "$WORK/db" && mkdir -m 0700 "$WORK/db"
  for f in db.sqlite db.sqlite-wal db.sqlite-shm; do
    d cp "$P-hold:/data/$f" - 2>/dev/null | tar -x -C "$WORK/db" 2>/dev/null || true
  done
  python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("SELECT version FROM database_versions WHERE id = 1").fetchone()[0])' \
    "$WORK/db/db.sqlite"
}

log "image CHÍNH THỨC $HS_OFFICIAL tạo DB trên volume trống (user ct-boot bằng CLI), rồi dừng"
start_hs "$HS_OFFICIAL"
V_OFFICIAL=$(version_of)
d exec "$P-hs" headscale users create ct-boot >/dev/null
d stop -t 60 "$P-hs" >/dev/null
DBV_OFFICIAL=$(db_version)

log "Headscale ĐƯỢC THỬ $HS_IMAGE trên DB đó (config_sha256 ${CONFIG_SHA:0:16}…)"
start_hs "$HS_IMAGE"
V_PATCHED=$(version_of)
[ "$V_PATCHED" = "v0.29.7 commit $EXPECT_COMMIT" ] || { echo "version của image được thử: $V_PATCHED"; exit 1; }
( umask 077; d exec "$P-hs" headscale apikeys create --expiration 3h -o json \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin))' > "$WORK/secrets/api_key" )

log "edge $CADDY_IMAGE — listener admin $EDGE_IP:$ADMIN_PORT"
d run -d --name "$P-edge" --network "$P-admin" --ip "$EDGE_IP" \
  -v "$WORK/edge/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$WORK/secrets/edge_token:/run/secrets/admin_token:ro" \
  "$CADDY_IMAGE" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
d network connect "$P-tenant" "$P-edge"
sleep 2
[ "$(d inspect -f '{{.State.Running}}' "$P-edge")" = true ] || { d logs "$P-edge"; exit 1; }

obs "env" "môi trường" "headscale được thử=$HS_IMAGE ($V_PATCHED); chính thức (tạo DB, pha 6)=$HS_OFFICIAL ($V_OFFICIAL); config_sha256=$CONFIG_SHA node.expiry=$NODE_EXPIRY; edge=$CADDY_IMAGE (khối admin của Caddyfile.tmpl); client=$TS_IMAGE; test build=$GO_IMAGE"

run_phase() {
  local n=$1 rc
  log "pha $n"
  d create --name "$P-run" --network "$P-admin" --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$WORK/bin:/hsct:ro" -v "$WORK/secrets:/secrets:ro" -v "$WORK/state:/state" \
    -e "HSCT_ADMIN_URL=http://$EDGE_IP:$ADMIN_PORT" -e "HSCT_SLUG=$SLUG" -e "HSCT_CONTROL_URL=http://hs-$SLUG:8080" \
    -e HSCT_SECRETS_DIR=/secrets -e HSCT_STATE_DIR=/state -e HSCT_OBS_FILE=/state/observations.jsonl \
    -e "HSCT_NODE_EXPIRY=$NODE_EXPIRY" -e "HSCT_EXPECT_COMMIT=$EXPECT_COMMIT" -e "HSCT_OFFICIAL_COMMIT=$OFFICIAL_COMMIT" \
    "$ALPINE_IMAGE" /hsct/hsct.test -test.v -test.count=1 -test.timeout=20m -test.run "^TestP${n}_" >/dev/null
  d network connect "$P-tenant" "$P-run"
  set +e
  d start -a "$P-run" > "$OUT/phase-$n.log" 2>&1
  rc=$?
  set -e
  d rm -f "$P-run" >/dev/null
  grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS|FAIL|ok)' "$OUT/phase-$n.log" | grep -v '=== RUN' || true
  if [ $rc -ne 0 ]; then tail -40 "$OUT/phase-$n.log"; log "pha $n thất bại"; return $rc; fi
}

finish() {
  cp "$WORK/state/observations.jsonl" "$OUT/observations.jsonl" 2>/dev/null || true
}

# ---------------------------------------------------------------- phases
run_phase 1 || { finish; exit 1; }

log "client chính thức $TS_IMAGE đăng ký bằng pre-auth key của pha 1"
d run -d --name "$P-ts" --network "$P-tenant" --tmpfs /var/lib/tailscale --tmpfs /tmp \
  -v "$WORK/state/official_authkey:/run/hsct/authkey:ro" \
  -e TS_AUTHKEY=file:/run/hsct/authkey -e TS_HOSTNAME=ct-official -e TS_USERSPACE=true \
  -e TS_STATE_DIR=/var/lib/tailscale -e TS_SOCKET=/tmp/tailscaled.sock -e TS_AUTH_ONCE=true -e TS_NO_LOGS_NO_SUPPORT=true \
  -e "TS_EXTRA_ARGS=--login-server=http://hs-$SLUG:8080" "$TS_IMAGE" >/dev/null
st=""
for _ in $(seq 1 60); do
  st=$(d exec "$P-ts" tailscale --socket=/tmp/tailscaled.sock status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState",""))' 2>/dev/null || true)
  [ "$st" = Running ] && break
  sleep 1
done
TS_VERSION=$(d exec "$P-ts" tailscale version 2>/dev/null | head -1 || true)
obs "V-21" "client chính thức" "BackendState=$st; tailscale version $TS_VERSION"
[ "$st" = Running ] || { d logs --tail 40 "$P-ts"; finish; exit 1; }

run_phase 2 || { finish; exit 1; }
d rm -f "$P-ts" >/dev/null

log "restart Headscale (policy rỗng đã lưu ⇒ kiểm hành vi lúc khởi động)"
d restart -t 60 "$P-hs" >/dev/null; wait_healthy
run_phase 3 || { finish; exit 1; }

log "làm đầy volume dữ liệu của Headscale"
d exec "$P-hold" sh -c 'cat /dev/zero > /data/fill 2>/dev/null; sync' || true
FREE=$(d exec "$P-hold" df -k /data | awk 'NR==2 {print $4}')
obs "V-26" "đĩa đầy" "volume dữ liệu tmpfs 32 MiB được lấp đầy (còn trống ${FREE} KiB) trước pha 4"
run_phase 4 || { finish; exit 1; }

log "giải phóng volume + restart Headscale"
d exec "$P-hold" rm -f /data/fill
d restart -t 60 "$P-hs" >/dev/null; wait_healthy
PROC_BEFORE=$(d inspect -f '{{.State.Pid}} started={{.State.StartedAt}} restarts={{.RestartCount}}' "$P-hs")
run_phase 5 || { finish; exit 1; }
PROC_AFTER=$(d inspect -f '{{.State.Status}} {{.State.Pid}} started={{.State.StartedAt}} restarts={{.RestartCount}}' "$P-hs")
obs "V-26" "bản vá: tiến trình Headscale qua pha 5 (AuthRegister với Auth ID SSH-check bị từ chối)" \
  "trước pha: pid $PROC_BEFORE; sau pha: $PROC_AFTER ⇒ cùng tiến trình, không restart"
if [ "$PROC_AFTER" != "running $PROC_BEFORE" ]; then
  echo "Headscale (bản vá) đã restart hoặc thoát trong pha 5: $PROC_BEFORE → $PROC_AFTER"; finish; exit 1
fi

log "ROLLBACK + ĐỐI CHỨNG ÂM: dừng bản vá, chạy image CHÍNH THỨC trên cùng volume dữ liệu"
d stop -t 60 "$P-hs" >/dev/null
DBV_PATCHED=$(db_version)
start_hs "$HS_OFFICIAL"
run_phase 6 || { finish; exit 1; }

STATE=$(d inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}' "$P-hs")
d logs "$P-hs" > "$WORK/hs.log" 2>&1 || true
python3 - "$WORK/hs.log" "$OUT/headscale-crash.log" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
red = lambda s: re.sub(r"hskey-(?:api|auth|authreq)-[A-Za-z0-9_-]+", "[REDACTED]", s)
idx = next((i for i, l in enumerate(lines) if l.startswith("panic:") or '"level":"panic"' in l), None)
out = [red(l) for l in (lines[idx:idx + 40] if idx is not None else lines[-20:])]
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(out) + "\n")
print(out[0] if out else "")
PY
PANIC=$(head -1 "$OUT/headscale-crash.log")
obs "V-26" "ĐỐI CHỨNG ÂM — container image CHÍNH THỨC sau AuthRegister(Auth ID SSH-check)" "container: $STATE; dòng đầu log: $PANIC"
log "container Headscale chính thức: $STATE"
case "$STATE|$PANIC" in
  "exited exit=2 "*"|panic: RegistrationData can only be used in registration requests") ;;
  *) echo "đối chứng âm không tái hiện crash của image chính thức"; finish; exit 1 ;;
esac

log "FORWARD: chạy lại bản vá trên DB do image chính thức ghi lần cuối"
DBV_OFFICIAL_AGAIN=$(db_version)
start_hs "$HS_IMAGE"
V_FORWARD=$(version_of)
obs "P2-T10a" "database_versions (RT-10) qua các lần đổi image trên cùng DB" \
  "chính thức tạo DB ⇒ $DBV_OFFICIAL; sau bản vá ⇒ $DBV_PATCHED; sau chính thức (rollback) ⇒ $DBV_OFFICIAL_AGAIN; bản vá khởi động lại ⇒ healthy ($V_FORWARD)"
if [ "$DBV_OFFICIAL $DBV_PATCHED $DBV_OFFICIAL_AGAIN" != "v0.29.7 v0.29.7 v0.29.7" ]; then
  echo "database_versions bất thường: $DBV_OFFICIAL $DBV_PATCHED $DBV_OFFICIAL_AGAIN"; finish; exit 1
fi
run_phase 7 || { finish; exit 1; }

finish
python3 - "$OUT/observations.jsonl" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
print(f"\n{len(rows)} quan sát:")
for r in rows:
    print(f"- [{r['quirk']}] {r['case']}: {r['observed'][:160]}")
PY
log "CONTRACT TEST: PASS"
