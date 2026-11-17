#!/usr/bin/env bash
# Test tích hợp compose driver của Host Agent trên Docker THẬT (P3-T02; master §11.3 bước 7–11, §14.2–§14.5) — chạy trên
# máy có Docker (VM build, runner GitHub). Không chạy trong `go test ./...` (build tag dockerintegration).
#
#   bash tests/integration/agent/run.sh                          # docker không cần sudo (runner GitHub)
#   DOCKER="sudo -n docker" AGENTIT_PREFIX=p3t02 bash ...        # VM build (docker cần sudo, tiền tố riêng)
#   AGENTIT_IMAGE=<image agent đã build> bash ...                # bỏ bước build image agent
#   make agent-it
#
# Cách làm: build image agent từ cây hiện tại (infrastructure/docker/agent/Dockerfile) và binary test
# (`go test -c -tags dockerintegration ./apps/agent`, CGO tắt, [images.golang]); chạy binary đó BÊN TRONG image agent
# với đúng hardening của compose agent: --network none, --read-only (+ tmpfs /tmp), --cap-drop ALL + CHOWN/FOWNER/
# DAC_OVERRIDE, no-new-privileges, user 0 — nên test này cũng là phép thử tập capability tối thiểu (§14.4); mount
# Docker socket và một thư mục gốc tạm (thay cho /opt/meshguard — KHÔNG BAO GIỜ /opt/meshguard) CÙNG đường dẫn trong và
# ngoài container. Test (apps/agent/integration_test.go) dựng một agent thật (socket, token, guard, compose driver),
# tạo tenant dùng-một-lần từ tham số có kiểu với image [images.mg-headscale] thật: thư mục → file → network → compose up
# → healthy → status; gọi lặp mọi lời gọi (idempotent); stop/start/restart; remove giữ data, hội tụ lại, ca âm (object
# trùng tên mang label lạ / không label ⇒ FOREIGN_OBJECT, không đụng gì), remove xóa data. Script chụp
# `docker ps -a`, `docker network ls` và cây thư mục gốc TRƯỚC và SAU — phải trùng nhau.
#
# Dải mạng: 10.250.240.0/20 dành riêng cho test này (trong pool tenant 10.250.0.0/16 của versions.lock, không chồng
# staging 10.250.0.0/24, e2e 10.250.23x, contract/isolation 10.250.25x); mặc định pool 10.250.240.0/24 và bốn /29 từ
# 10.250.240.0 (AGENTIT_NET). Script từ chối chạy nếu một network Docker đang có chồng lên các /29 đó.
# Tài nguyên mang tiền tố $AGENTIT_PREFIX (mặc định agentit): image <prefix>-agent:it, container <prefix>-run,
# network/container mg-t-<prefix>-*/mg-hs-<prefix>-*, volume cache Go <prefix>-gomod/<prefix>-gocache (giữ lại;
# AGENTIT_KEEP_CACHE=0 để xóa). Kết quả: $AGENTIT_OUT/agentit.log, snapshot before/after.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${AGENTIT_PREFIX:-agentit}
POOL=${AGENTIT_POOL:-10.250.240.0/24}
NET=${AGENTIT_NET:-10.250.240.0/29}
KEEP_CACHE=${AGENTIT_KEEP_CACHE:-1}
OUT=${AGENTIT_OUT:-$(mktemp -d -t agentit-out.XXXXXX)}
mkdir -p "$OUT"
log() { printf '[agentit %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

lock() {  # <image name in versions.lock> → image@index
  python3 - "$ROOT/versions.lock" "$1" <<'PY'
import re, sys, tomllib
img = tomllib.load(open(sys.argv[1], "rb"))["images"].get(sys.argv[2], {})
print(f"{img['image']}@{img['index']}" if re.fullmatch(r"sha256:[0-9a-f]{64}", str(img.get("index", ""))) else "")
PY
}
GO_IMAGE=$(lock golang); HS_IMAGE=$(lock mg-headscale); ALPINE_IMAGE=$(lock alpine)
[ -n "$HS_IMAGE" ] || { echo "[images.mg-headscale] chưa pin trong versions.lock"; exit 1; }

# the four /29 of the test must be inside the pool, inside 10.250.240.0/20, and free on this Docker host
python3 - "$POOL" "$NET" <<'PY' || exit 1
import ipaddress, sys
pool, net = ipaddress.ip_network(sys.argv[1]), ipaddress.ip_network(sys.argv[2])
reserved = ipaddress.ip_network("10.250.240.0/20")
nets = [ipaddress.ip_network(f"{net.network_address + 8 * i}/29") for i in range(4)]
if net.prefixlen != 29 or not pool.subnet_of(reserved) or not all(n.subnet_of(pool) for n in nets):
    sys.exit("AGENTIT_NET must be a /29 with its next three /29 inside AGENTIT_POOL, inside 10.250.240.0/20")
PY
used=$(d network ls -q | xargs -r "${DOCKER_CMD[@]}" network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -v '^$' || true)
python3 - "$NET" $used <<'PY' || { echo "một network Docker đang dùng dải của test — đổi AGENTIT_NET"; exit 1; }
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1])
mine = ipaddress.ip_network(f"{net.network_address}/27")
for s in sys.argv[2:]:
    try:
        other = ipaddress.ip_network(s)
    except ValueError:
        continue
    if other.version == 4 and other.overlaps(mine):
        sys.exit(f"overlap with {s}")
PY

WORK=$(mktemp -d -t agentit-work.XXXXXX)
IT_ROOT=$(mktemp -d /tmp/"$P"-root.XXXXXX)   # the /opt/meshguard of the test (same path inside the container)
chmod 0755 "$IT_ROOT"
built_image=""
cleanup() {
  d rm -f "$P-run" >/dev/null 2>&1 || true
  # leftovers of a failed run (the test removes its own objects): only names derived from the prefix
  for c in $(d ps -a --format '{{.Names}}' | grep -E "^mg-hs-$P-" || true); do d rm -f "$c" >/dev/null 2>&1 || true; done
  for n in $(d network ls --format '{{.Name}}' | grep -E "^mg-t-$P-" || true); do d network rm "$n" >/dev/null 2>&1 || true; done
  # files of the test root belong to root (run_uid) — removed through a pinned alpine container
  d run --rm --network none -v "$IT_ROOT:/r" "$ALPINE_IMAGE" sh -c 'rm -rf /r/* /r/.[!.]*' >/dev/null 2>&1 || true
  rmdir "$IT_ROOT" 2>/dev/null || true
  [ -n "$built_image" ] && d image rm "$built_image" >/dev/null 2>&1 || true
  [ "$KEEP_CACHE" = 1 ] || d volume rm -f "$P-gomod" "$P-gocache" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

snapshot() {
  d ps -a --format '{{.ID}} {{.Names}} {{.State}} {{.Image}}' | sort
  d network ls --format '{{.ID}} {{.Name}} {{.Driver}}' | sort
  (cd "$IT_ROOT" && find . -printf '%M %u:%g %s %p\n' 2>/dev/null | sort)
}

IMAGE=${AGENTIT_IMAGE:-}
if [ -z "$IMAGE" ]; then
  IMAGE="$P-agent:it"
  log "build image agent từ cây hiện tại → $IMAGE"
  d build -q -f "$ROOT/infrastructure/docker/agent/Dockerfile" --build-arg VERSION=agentit --build-arg COMMIT=test -t "$IMAGE" "$ROOT" >/dev/null
  built_image=$IMAGE
fi
log "build binary test (go test -c -tags dockerintegration ./apps/agent) trong $GO_IMAGE"
mkdir -p "$WORK/bin"
d volume create "$P-gomod" >/dev/null
d volume create "$P-gocache" >/dev/null
d run --rm --network bridge -v "$ROOT:/src:ro" -v "$P-gomod:/go/pkg/mod" -v "$P-gocache:/root/.cache/go-build" -v "$WORK/bin:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 -w /src "$GO_IMAGE" \
  sh -c "go vet -tags dockerintegration ./apps/agent && go test -c -tags dockerintegration -o /out/agent.test ./apps/agent && chown $(id -u):$(id -g) /out/agent.test"

snapshot > "$OUT/before.txt"
log "chạy test trong image agent (network none, read-only, cap_drop ALL + CHOWN/FOWNER/DAC_OVERRIDE); root $IT_ROOT, mạng $NET…"
rc=0
d run --name "$P-run" --network none --read-only --tmpfs /tmp:size=64m,mode=1777 --cap-drop ALL \
  --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --security-opt no-new-privileges --user 0:0 \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$IT_ROOT:$IT_ROOT" -v "$WORK/bin/agent.test:/it/agent.test:ro" \
  -e MG_IT_ROOT="$IT_ROOT" -e MG_IT_IMAGE="$HS_IMAGE" -e MG_IT_PREFIX="$P" -e MG_IT_POOL="$POOL" -e MG_IT_NET="$NET" \
  --entrypoint /it/agent.test "$IMAGE" -test.v -test.count=1 -test.timeout=20m -test.run '^TestComposeDriverEndToEnd$' \
  > "$OUT/agentit.log" 2>&1 || rc=$?
d rm -f "$P-run" >/dev/null 2>&1 || true
snapshot > "$OUT/after.txt"
grep -E '^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok)|integration_test.go:' "$OUT/agentit.log" | grep -v '=== RUN' || true
if ! diff -u "$OUT/before.txt" "$OUT/after.txt" > "$OUT/snapshot.diff"; then
  log "SNAPSHOT KHÁC (docker ps -a / network ls / thư mục gốc trước và sau):"; cat "$OUT/snapshot.diff"; rc=1
else
  log "snapshot trước = sau: $(grep -c . "$OUT/before.txt") dòng (container, network, cây thư mục gốc)"
fi
if [ "$rc" = 0 ] && grep -q '^--- PASS: TestComposeDriverEndToEnd' "$OUT/agentit.log"; then
  log "AGENT DRIVER IT: PASS"
else
  log "AGENT DRIVER IT: FAIL (log: $OUT/agentit.log)"; tail -40 "$OUT/agentit.log"; exit 1
fi
