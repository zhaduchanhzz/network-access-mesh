#!/usr/bin/env bash
# Test tích hợp Host Agent trên Docker THẬT — compose driver (P3-T02; master §11.3 bước 7–11, §14.2–§14.5) và các thao
# tác của P3-T03 (ValidateConfig, BootstrapPolicy, BootstrapApiKey, gắn/gỡ edge, edge supervisor, start guard — §11.4).
# Chạy trên máy có Docker (VM build, runner GitHub). Không chạy trong `go test ./...` (build tag dockerintegration).
#
#   bash tests/integration/agent/run.sh                          # docker không cần sudo (runner GitHub)
#   DOCKER="sudo -n docker" AGENTIT_PREFIX=p3t03 bash ...        # VM build (docker cần sudo, tiền tố riêng)
#   AGENTIT_IMAGE=<image agent đã build> bash ...                # bỏ bước build image agent
#   AGENTIT_WAIT=3600 bash ...                                   # chờ (tối đa N giây) khi lần chạy agent-it khác đang giữ dải
#   make agent-it
#
# Cách làm: build image agent từ cây hiện tại (infrastructure/docker/agent/Dockerfile) và binary test
# (`go test -c -tags dockerintegration ./apps/agent`, CGO tắt, [images.golang]); chạy binary đó BÊN TRONG image agent
# với đúng hardening của compose agent: --network none, --read-only (+ tmpfs /tmp), --cap-drop ALL + CHOWN/FOWNER/
# DAC_OVERRIDE, no-new-privileges, user 0 — nên test này cũng là phép thử tập capability tối thiểu (§14.4); mount
# Docker socket và một thư mục gốc tạm (thay cho /opt/meshguard — KHÔNG BAO GIỜ /opt/meshguard) CÙNG đường dẫn trong và
# ngoài container. Hai test (apps/agent/integration_test.go, integration_ops_test.go) dựng một agent thật (socket,
# token, guard, compose driver) — không PostgreSQL, không worker — và tạo tenant dùng-một-lần từ tham số có kiểu với
# image [images.mg-headscale] thật:
#   TestComposeDriverEndToEnd   thư mục → file → network → compose up → healthy → status; idempotent; stop/start/restart;
#                               remove giữ data, hội tụ lại, ca âm FOREIGN_OBJECT; remove xóa data;
#   TestAgentOperationsEndToEnd configtest trong container tạm (data/ không bị đụng); policy + API key qua CLI trong
#                               container (key không bao giờ vào log); gắn edge (alias trùng ⇒ CONFLICT, thành viên lạ
#                               ⇒ FOREIGN_OBJECT); edge (container alpine <prefix>-edge, network <prefix>-edgenet,
#                               gw_priority 1) bị tạo lại ⇒ supervisor gắn lại đúng tập network có cờ; start guard (data/
#                               rỗng, Noise key khác, db.sqlite mất) ⇒ không start, xóa cờ, gỡ edge, sự kiện Critical.
#   TestReconcileReportsForeignObjectsUntouched (P3-T12, apps/agent/reconcile_integration_test.go) reconcile chỉ báo
#                               cáo — network/container mang label meshguard dựng tay được báo là lạ, drift của tenant
#                               được báo, host không đổi, agent chỉ nhận lời gọi đọc.
#   TestReconfigureEndToEnd     (P3-T13, apps/agent/reconfigure_integration_test.go) state machine instance.reconfigure
#                               của orchestrator lái agent thật trên một instance đã kích hoạt: đổi hợp lệ ⇒ version mới
#                               trên đĩa, restart, healthy, log.level mới có hiệu lực, data/ không đổi; cấu hình qua
#                               configtest nhưng hỏng lúc chạy (listen_addr trùng cổng metrics) ⇒ tự lùi về version trước.
#   TestBackupRestoreEndToEnd   (P3-T11, apps/agent/integration_backup_test.go) backup/restore v1 với sqlite3 + age thật
#                               của image agent: backup online (VACUUM INTO, data/ chỉ-đọc) dưới tải ghi (V-12;
#                               MG_IT_V12_ROUNDS lượt, mặc định 3) và cold copy; manifest ký; đường DR (identity khôi
#                               phục giải mã bằng age) — archive của A không có byte nào của B; T-15 (data key của B,
#                               manifest bị sửa / ký khóa khác, archive A vào B ⇒ từ chối trước khi giải mã); restore +
#                               PostRestoreReconcile (IT-16: key cũ chết, pre-auth key hết hạn, node thu hồi vẫn hết
#                               hạn, route bỏ duyệt, user offboard); ID số bị cấp lại sau restore (node/user mới nhận
#                               ID của đối tượng tạo sau backup — machine key khác; pre-auth key theo ID cũ rơi vào
#                               user mới, theo ID phân giải bằng tên thì đúng user); AC-19 (B không đổi); IT-15 (symlink sang file của
#                               B, FIFO, file thưa 1 TiB, DB hỏng ⇒ backup và start guard fail-closed + security_event); cuối cùng restore bản lấy dưới tải ghi (V-12).
#   TestUpgradeEndToEnd         (P3-T13a, apps/agent/upgrade_integration_test.go) state machine instance.upgrade và
#                               instance.restart của orchestrator lái agent thật với CẢ HAI image trong allowlist
#                               ([images.mg-headscale] và [images.headscale] chính thức — MG_IT_IMAGE_OFFICIAL): configtest
#                               của binary đích trên bản sao cold backup bị buộc lỗi (policy đang lưu không hợp lệ ghi vào
#                               DB của BẢN SAO ngay trước configtest) ⇒ image cũ chạy lại, data/ trùng từng
#                               byte giữa lúc dừng và lúc start lại; nâng bản vá → chính thức thành công; lỗi sau khi đổi
#                               image (contract smoke) ⇒ tự lùi bằng restore cold backup; restart với policy bị đổi ngoài
#                               luồng ⇒ áp lại; db.sqlite bị thay bằng DB trống ⇒ edge bị gỡ + Critical.
#   TestQuarantineReleaseEndToEnd (P3-T18, apps/agent/quarantine_integration_test.go) edge Caddy thật ([images.caddy],
#                               site tenant của infrastructure/caddy/Caddyfile.tmpl render ở đây, HTTP :8080): quarantine
#                               ⇒ hostname trả 404 như tenant không tồn tại, container dừng, data/ không đổi; supervisor,
#                               start/restart/compose up/attach và bỏ qua agent bằng tay không làm nó phục vụ lại; release
#                               ⇒ start guard + healthy + policy đúng, gắn edge, post-start gate qua API, /key 200.
# Fingerprint Noise key do container trợ giúp tính bằng chính image agent (MG_IT_HELPER_IMAGE = image id).
# AGENTIT_RUN=<regex> chỉ chạy một phần các test (phát triển; PASS của bộ đầy đủ cần mọi test).
# Script chụp `docker ps -a`, `docker network ls` và cây thư mục gốc TRƯỚC và SAU — phải trùng nhau.
#
# Dải mạng: 10.250.240.0/20 dành riêng cho agent-it (trong pool tenant 10.250.0.0/16 của versions.lock, không chồng
# staging 10.250.0.0/24, e2e 10.250.23x, contract/isolation 10.250.25x); mặc định pool 10.250.240.0/24 và tám /29 từ
# 10.250.240.0 (AGENTIT_NET). Một lần chạy agent-it khác (tiền tố khác) đang có network trong 10.250.240.0/20 ⇒ script
# từ chối chạy (exit 75), hoặc chờ tối đa AGENTIT_WAIT giây (kiểm lại mỗi 15 s); network nào khác chồng lên tám /29 ⇒
# từ chối. Tài nguyên mang tiền tố $AGENTIT_PREFIX (mặc định agentit): image <prefix>-agent:it, container <prefix>-run,
# <prefix>-edge, <prefix>-impostor, network <prefix>-edgenet, <prefix>-alias, network/container
# mg-t-<prefix>-*/mg-hs-<prefix>-*, container trợ giúp mg-helper-<prefix>-*, volume cache Go <prefix>-gomod/
# <prefix>-gocache (giữ lại; AGENTIT_KEEP_CACHE=0 để xóa). Kết quả: $AGENTIT_OUT/agentit.log, snapshot before/after.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${AGENTIT_PREFIX:-agentit}
POOL=${AGENTIT_POOL:-10.250.240.0/24}
NET=${AGENTIT_NET:-10.250.240.0/29}
KEEP_CACHE=${AGENTIT_KEEP_CACHE:-1}
WAIT=${AGENTIT_WAIT:-0}
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
GO_IMAGE=$(lock golang); HS_IMAGE=$(lock mg-headscale); ALPINE_IMAGE=$(lock alpine); CADDY_IMAGE=$(lock caddy)
OFFICIAL_IMAGE=$(lock headscale)
[ -n "$HS_IMAGE" ] || { echo "[images.mg-headscale] chưa pin trong versions.lock"; exit 1; }
[ -n "$OFFICIAL_IMAGE" ] || { echo "[images.headscale] chưa pin trong versions.lock"; exit 1; }

# the eight /29 of the test must be inside the pool, inside 10.250.240.0/20
python3 - "$POOL" "$NET" <<'PY' || exit 1
import ipaddress, sys
pool, net = ipaddress.ip_network(sys.argv[1]), ipaddress.ip_network(sys.argv[2])
reserved = ipaddress.ip_network("10.250.240.0/20")
nets = [ipaddress.ip_network(f"{net.network_address + 8 * i}/29") for i in range(8)]
if net.prefixlen != 29 or not pool.subnet_of(reserved) or not all(n.subnet_of(pool) for n in nets):
    sys.exit("AGENTIT_NET must be a /29 with its next seven /29 inside AGENTIT_POOL, inside 10.250.240.0/20")
PY

# networks of the host as "<name> <subnet>…" lines
subnets() {
  d network ls -q | xargs -r "${DOCKER_CMD[@]}" network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true
}
# busy: another agent-it run (any other network in 10.250.240.0/20) or anything overlapping our eight /29 ⇒ exit 3/4
check_free() {
  subnets | python3 -c '
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1]); mine = ipaddress.ip_network(f"{net.network_address}/26")
reserved = ipaddress.ip_network("10.250.240.0/20"); others = []
for line in sys.stdin:
    name, *subs = line.split()
    for s in subs:
        try:
            n = ipaddress.ip_network(s)
        except ValueError:
            continue
        if n.version != 4:
            continue
        if n.overlaps(mine):
            print(f"{name} {s} chồng dải của test"); sys.exit(4)
        if n.overlaps(reserved):
            others.append(f"{name} {s}")
if others:
    print("lần chạy agent-it khác đang giữ 10.250.240.0/20: " + ", ".join(others)); sys.exit(3)
' "$NET"
}
waited=0
while true; do
  rc=0; msg=$(check_free) || rc=$?
  [ "$rc" = 0 ] && break
  if [ "$rc" = 4 ] || [ "$waited" -ge "$WAIT" ]; then
    echo "$msg — đổi AGENTIT_NET hoặc chờ (AGENTIT_WAIT)"; exit 75
  fi
  [ "$waited" = 0 ] && log "chờ: $msg"
  sleep 15; waited=$((waited + 15))
done

WORK=$(mktemp -d -t agentit-work.XXXXXX)
IT_ROOT=$(mktemp -d /tmp/"$P"-root.XXXXXX)   # the /opt/meshguard of the test (same path inside the container)
chmod 0755 "$IT_ROOT"
built_image=""
cleanup() {
  d rm -f "$P-run" >/dev/null 2>&1 || true
  # leftovers of a failed run (the tests remove their own objects): only names derived from the prefix
  for c in $(d ps -a --format '{{.Names}}' | grep -E "^(mg-hs-$P-|mg-helper-$P-|$P-edge\$|$P-cedge\$|$P-impostor\$)" || true); do d rm -f "$c" >/dev/null 2>&1 || true; done
  for n in $(d network ls --format '{{.Name}}' | grep -E "^(mg-t-$P-|$P-edgenet\$|$P-cedgenet\$|$P-alias\$)" || true); do d network rm "$n" >/dev/null 2>&1 || true; done
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
HELPER_IMAGE=$(d image inspect -f '{{.Id}}' "$IMAGE")   # the fingerprint helper runs the agent's own image (pinned by id)
d image inspect "$ALPINE_IMAGE" >/dev/null 2>&1 || d pull -q "$ALPINE_IMAGE" >/dev/null   # the fake edge (before the snapshot)
d image inspect "$CADDY_IMAGE" >/dev/null 2>&1 || d pull -q "$CADDY_IMAGE" >/dev/null     # the Caddy edge of P3-T18
# the tenant site block of the production edge template (P3-T18): allow-list, upstream hs-<label>.:8080, 502/503/504 ⇒ 404;
# plain HTTP on :8080 for mesh.agentit.test — the template's TLS, access log and listener binding are left out
mkdir -p "$WORK/edge"
python3 - "$ROOT/infrastructure/caddy/Caddyfile.tmpl" "$WORK/edge/Caddyfile" <<'PY'
import string, sys
t = open(sys.argv[1], encoding="utf-8").read()
start = t.index("*.${mesh_domain}${tunnel_tls_site} {")
end = t.index("\n}\n", start) + 3
mesh = "mesh.agentit.test"
block = string.Template(t[start:end]).substitute(mesh_domain=mesh, mesh_domain_re=mesh.replace(".", "\\."),
    tunnel_tls_site="", tunnel_guard="", public_entry_ipv4="192.0.2.10")
lines = [ln for ln in block.splitlines() if ln.strip() not in ("import access_log", "import tls_acme")]
lines[0] = "http://*." + mesh + ":8080 {"
head = "{\n\tadmin off\n\tpersist_config off\n\tauto_https off\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n\n"
open(sys.argv[2], "w", encoding="utf-8").write(head + "\n".join(lines) + "\n")
PY
chmod 0755 "$WORK" "$WORK/edge"; chmod 0644 "$WORK/edge/Caddyfile"
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
  -e MG_IT_HELPER_IMAGE="$HELPER_IMAGE" -e MG_IT_ALPINE="$ALPINE_IMAGE" -e MG_IT_V12_ROUNDS="${MG_IT_V12_ROUNDS:-3}" \
  -e MG_IT_CADDY="$CADDY_IMAGE" -e MG_IT_EDGE_CADDYFILE="$WORK/edge/Caddyfile" -v "$WORK/edge:$WORK/edge:ro" \
  -e MG_IT_IMAGE_OFFICIAL="$OFFICIAL_IMAGE" \
  --entrypoint /it/agent.test "$IMAGE" -test.v -test.count=1 -test.timeout=60m \
  -test.run "${AGENTIT_RUN:-^(TestComposeDriverEndToEnd|TestAgentOperationsEndToEnd|TestReconcileReportsForeignObjectsUntouched|TestReconfigureEndToEnd|TestBackupRestoreEndToEnd|TestQuarantineReleaseEndToEnd|TestUpgradeEndToEnd)\$}" \
  > "$OUT/agentit.log" 2>&1 || rc=$?
d rm -f "$P-run" >/dev/null 2>&1 || true
snapshot > "$OUT/after.txt"
grep -E '^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok)|(integration(_ops|_backup)?|reconfigure_integration|quarantine_integration|upgrade_integration)_test.go:' "$OUT/agentit.log" | grep -v '=== RUN' || true
if ! diff -u "$OUT/before.txt" "$OUT/after.txt" > "$OUT/snapshot.diff"; then
  log "SNAPSHOT KHÁC (docker ps -a / network ls / thư mục gốc trước và sau):"; cat "$OUT/snapshot.diff"; rc=1
else
  log "snapshot trước = sau: $(grep -c . "$OUT/before.txt") dòng (container, network, cây thư mục gốc)"
fi
if [ "$rc" = 0 ] && grep -q '^--- PASS: TestComposeDriverEndToEnd' "$OUT/agentit.log" && grep -q '^--- PASS: TestAgentOperationsEndToEnd' "$OUT/agentit.log" \
  && grep -q '^--- PASS: TestReconcileReportsForeignObjectsUntouched' "$OUT/agentit.log" && grep -q '^--- PASS: TestReconfigureEndToEnd' "$OUT/agentit.log" \
  && grep -q '^--- PASS: TestBackupRestoreEndToEnd' "$OUT/agentit.log" \
  && grep -q '^--- PASS: TestQuarantineReleaseEndToEnd' "$OUT/agentit.log" && grep -q '^--- PASS: TestUpgradeEndToEnd' "$OUT/agentit.log"; then
  log "AGENT DRIVER IT: PASS"
elif [ "$rc" = 0 ] && [ -n "${AGENTIT_RUN:-}" ]; then
  log "AGENT DRIVER IT: PASS (một phần: $AGENTIT_RUN)"
else
  log "AGENT DRIVER IT: FAIL (log: $OUT/agentit.log)"; tail -60 "$OUT/agentit.log"; exit 1
fi
