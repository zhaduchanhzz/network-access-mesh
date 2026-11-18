#!/usr/bin/env bash
# Harness tiêm lỗi của máy trạng thái provisioning (P3-T07; master §11.3, §20) — orchestrator THẬT (River, PostgreSQL,
# SecretStore, placer, adapter Headscale qua edge) điều khiển Host Agent THẬT trên Docker THẬT với image Headscale THẬT
# ([images.mg-headscale]); tiêm lỗi tại từng bước (package faultinject — decorator quanh collaborator của orchestrator,
# không có hook nào trong mã production) và sau mỗi ca chạy bộ phát hiện tài nguyên mồ côi (package orphans). P3-T09:
# deprovision (§11.4) qua đường 2P — backup cuối THẬT (container trợ giúp của agent, manifest ký bằng khóa của nghi thức
# thử do vai trò keygen của binary test sinh), RemoveInstance(DELETE_ARCHIVED), hủy DEK sau grace period rút ngắn
# (PIT_KEY_GRACE, mặc định 20s) — ca E2E-73…E2E-75, và cuối lần chạy deprovision MỌI tenant của lần chạy.
# Chạy trên máy có Docker (VM build, runner GitHub). Không chạy trong `go test ./...` (build tag dockerintegration).
#
#   bash tests/integration/provisioning/run.sh                       # docker không cần sudo (runner GitHub)
#   DOCKER="sudo -n docker" PIT_PREFIX=p3t07pit bash ...             # VM build (docker cần sudo, tiền tố riêng)
#   PIT_IMAGE=<image agent đã build> bash ...                        # bỏ bước build image agent
#   PIT_WAIT=3600 bash ...                                           # chờ (tối đa N giây) khi dải mạng đang bị giữ
#   PIT_RUN='^TestProvisioningFaultInjection$/^E2E-49' bash ...      # chỉ một phần các ca (phát triển; PASS cần cả bộ)
#   PIT_RUN='^TestPostRestoreReconcile$' bash ...                     # chỉ E2E-72 (P3-T17: restore PostgreSQL cũ hơn)
#   PIT_RUN='^TestBackfillAdoptedInstance$' bash ...                  # chỉ E2E-84 (P3-T14b: instance dựng tay + adopt → backfill)
#   make provisioning-it
#
# Dựng (mọi image pin digest trong versions.lock, mọi tài nguyên mang tiền tố $PIT_PREFIX, xóa khi thoát):
#   <prefix>-pg     PostgreSQL [images.postgres] — mật khẩu superuser một lần, chỉ trong env-file 0600 của thư mục tạm;
#   <prefix>-agent  image agent build từ cây, chạy ĐÚNG như compose mg-agent: network none, rootfs chỉ đọc, cap_drop ALL
#                   + CHOWN/FOWNER/DAC_OVERRIDE, no-new-privileges, user 0; socket 0660 nhóm 20003, peer UID 65532;
#                   tenants/backups/run/cfg dưới một gốc tạm (/tmp/<prefix>-root.XXXXXX — KHÔNG BAO GIỜ /opt/meshguard)
#                   mount cùng đường dẫn; edge = <prefix>-edge trên network <prefix>-net;
#   <prefix>-edge   binary test ở vai trò edge (listener admin :8081 + public :8080 như Caddyfile.tmpl), [images.alpine],
#                   UID 65532 nhóm 20003, rootfs chỉ đọc, cap_drop ALL; gw_priority 1 trên <prefix>-net (như mg-edge);
#   <prefix>-run    binary test ở vai trò harness, UID 65532 + nhóm 20003 (danh tính của worker) + nhóm của Docker socket
#                   (bộ phát hiện chỉ ĐỌC Docker; E2E-72 chỉ `docker exec` pg_dump/pg_restore trong <prefix>-pg), gốc
#                   tạm mount chỉ đọc; tự khởi chạy các tiến trình worker con.
#
# Dải mạng: network tenant của lần chạy lấy từ PIT_POOL (mặc định 10.250.224.0/24 — trong pool tenant 10.250.0.0/16, không
# chồng staging 10.250.0.0/24, e2e 10.250.23x, agent-it/contract/isolation 10.250.240.0/20); network điều khiển
# <prefix>-net = PIT_CTL_NET (mặc định 10.249.224.0/28). Một network Docker nào đang chồng hai dải này ⇒ từ chối
# (exit 75) hoặc chờ PIT_WAIT giây (kiểm lại mỗi 15 s). Kết quả: $PIT_OUT/pit.log (log test), agent.log, edge.log,
# workers/ (log từng tiến trình worker), leftovers.txt, snapshot before/after (đối tượng mang tiền tố của lần chạy).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${PIT_PREFIX:-pit}
POOL=${PIT_POOL:-10.250.224.0/24}
CTL=${PIT_CTL_NET:-10.249.224.0/28}
RUN_UIDS=${PIT_RUN_UIDS:-39200-39299}
KEEP_CACHE=${PIT_KEEP_CACHE:-1}
WAIT=${PIT_WAIT:-0}
OUT=${PIT_OUT:-$(mktemp -d -t pit-out.XXXXXX)}
WORKER_UID=65532
WORKER_GID=20003
BASE_DOMAIN=pit.test
PUBLIC_IPV4=192.0.2.10
mkdir -p "$OUT"
log() { printf '[pit %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

[[ "$P" =~ ^[a-z][a-z0-9]{1,15}$ ]] || { echo "PIT_PREFIX: [a-z][a-z0-9]{1,15} (slug của tenant thử = <prefix>-<ca>)"; exit 2; }

lock() {  # <image name in versions.lock> → image@index
  python3 - "$ROOT/versions.lock" "$1" <<'PY'
import re, sys, tomllib
img = tomllib.load(open(sys.argv[1], "rb"))["images"].get(sys.argv[2], {})
print(f"{img['image']}@{img['index']}" if re.fullmatch(r"sha256:[0-9a-f]{64}", str(img.get("index", ""))) else "")
PY
}
GO_IMAGE=$(lock golang); HS_IMAGE=$(lock mg-headscale); ALPINE_IMAGE=$(lock alpine); PG_IMAGE=$(lock postgres)
[ -n "$HS_IMAGE" ] || { echo "[images.mg-headscale] chưa pin trong versions.lock"; exit 1; }
HS_DIGEST=${HS_IMAGE#*@}
HS_VERSION=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["images"]["headscale"]["tag"])' "$ROOT/versions.lock")

python3 - "$POOL" "$CTL" "$RUN_UIDS" <<'PY' || exit 2
import ipaddress, re, sys
pool, ctl = ipaddress.ip_network(sys.argv[1]), ipaddress.ip_network(sys.argv[2])
tenant = ipaddress.ip_network("10.250.0.0/16")
taken = [ipaddress.ip_network(n) for n in ("10.250.0.0/24", "10.250.240.0/20")] + \
        [ipaddress.ip_network(f"10.250.{i}.0/24") for i in range(230, 240)]
if not pool.subnet_of(tenant) or pool.prefixlen > 26 or any(pool.overlaps(n) for n in taken):
    sys.exit("PIT_POOL: một dải ≤ /26 trong 10.250.0.0/16, ngoài staging, e2e 10.250.23x và 10.250.240.0/20")
if ctl.overlaps(tenant) or ctl.prefixlen > 28:
    sys.exit("PIT_CTL_NET: ≥ /28, ngoài pool tenant 10.250.0.0/16")
m = re.fullmatch(r"(\d+)-(\d+)", sys.argv[3])
if not m or not 1000 <= int(m[1]) < int(m[2]) or int(m[2]) - int(m[1]) < 31 or 65532 in range(int(m[1]), int(m[2]) + 1):
    sys.exit("PIT_RUN_UIDS: lo-hi (≥ 32 UID, không chứa 65532 của worker)")
PY

subnets() {
  d network ls -q | xargs -r "${DOCKER_CMD[@]}" network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true
}
check_free() {  # exit 4: một network chồng dải của lần chạy
  subnets | python3 -c '
import ipaddress, sys
mine = [ipaddress.ip_network(a) for a in sys.argv[1:]]
for line in sys.stdin:
    name, *subs = line.split()
    for s in subs:
        try:
            n = ipaddress.ip_network(s)
        except ValueError:
            continue
        if n.version == 4 and any(n.overlaps(m) for m in mine):
            print(f"{name} {s} chồng dải của lần chạy"); sys.exit(4)
' "$POOL" "$CTL"
}
waited=0
while true; do
  rc=0; msg=$(check_free) || rc=$?
  [ "$rc" = 0 ] && break
  if [ "$waited" -ge "$WAIT" ]; then echo "$msg — đổi PIT_POOL/PIT_CTL_NET hoặc chờ (PIT_WAIT)"; exit 75; fi
  [ "$waited" = 0 ] && log "chờ: $msg"
  sleep 15; waited=$((waited + 15))
done

WORK=$(mktemp -d -t pit-work.XXXXXX)
chmod 0711 "$WORK"
mkdir -m 0700 "$WORK/secrets" "$WORK/bin"
IT_ROOT=$(mktemp -d /tmp/"$P"-root.XXXXXX)   # the /opt/meshguard of the test host (same path in every container)
chmod 0755 "$IT_ROOT"
built_image=""
names_re="^(mg-hs-$P-|mg-helper-$P-|mg-t-$P-|$P-(pg|agent|edge|run|net)\$)"
cleanup() {
  for c in "$P-run" "$P-edge" "$P-agent" "$P-pg"; do d rm -f "$c" >/dev/null 2>&1 || true; done
  for c in $(d ps -a --format '{{.Names}}' | grep -E "^(mg-hs-$P-|mg-helper-$P-)" || true); do d rm -f "$c" >/dev/null 2>&1 || true; done
  for n in $(d network ls --format '{{.Name}}' | grep -E "^(mg-t-$P-|$P-net\$)" || true); do d network rm "$n" >/dev/null 2>&1 || true; done
  # instance directories belong to root and run_uid — removed through a pinned alpine container (never /opt/meshguard)
  # (only while it exists: a missing bind source would be created by the daemon, as root)
  if [ -d "$IT_ROOT" ]; then
    d run --rm --network none -v "$IT_ROOT:/r" "$ALPINE_IMAGE" sh -c 'rm -rf /r/* /r/.[!.]*' >/dev/null 2>&1 || true
    rmdir "$IT_ROOT" 2>/dev/null || true
  fi
  [ -n "$built_image" ] && d image rm "$built_image" >/dev/null 2>&1 || true
  [ "$KEEP_CACHE" = 1 ] || d volume rm -f "$P-gomod" "$P-gocache" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

snapshot() {  # objects of this run only (the host may be shared): containers and networks with the run's prefix
  d ps -a --format '{{.Names}} {{.State}}' | grep -E "$names_re" | sort || true
  d network ls --format '{{.Name}} {{.Driver}}' | grep -E "$names_re" | sort || true
}
snapshot > "$OUT/before.txt"

IMAGE=${PIT_IMAGE:-}
if [ -z "$IMAGE" ]; then
  IMAGE="$P-agent:it"
  log "build image agent từ cây hiện tại → $IMAGE"
  d build -q -f "$ROOT/infrastructure/docker/agent/Dockerfile" --build-arg VERSION=pit --build-arg COMMIT=test -t "$IMAGE" "$ROOT" >/dev/null
  built_image=$IMAGE
fi
HELPER_IMAGE=$(d image inspect -f '{{.Id}}' "$IMAGE")   # the fingerprint helper runs the agent's own image (by id)
for img in "$ALPINE_IMAGE" "$PG_IMAGE" "$HS_IMAGE"; do
  d image inspect "$img" >/dev/null 2>&1 || d pull -q "$img" >/dev/null
done
log "build binary test (go test -c -tags dockerintegration ./tests/integration/provisioning) trong $GO_IMAGE"
d volume create "$P-gomod" >/dev/null
d volume create "$P-gocache" >/dev/null
d run --rm --network bridge -v "$ROOT:/src:ro" -v "$P-gomod:/go/pkg/mod" -v "$P-gocache:/root/.cache/go-build" -v "$WORK/bin:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e CGO_ENABLED=0 -w /src "$GO_IMAGE" \
  sh -c "go vet -tags dockerintegration ./tests/integration/provisioning/... && go test -c -tags dockerintegration -o /out/pit.test ./tests/integration/provisioning && chown $(id -u):$(id -g) /out/pit.test"
chmod 0755 "$WORK/bin" "$WORK/bin/pit.test"

log "nghi thức khóa thử (P3-T09): khóa ký manifest + khóa công khai + recipient khôi phục (vai trò keygen của binary test)"
mkdir -m 0700 "$WORK/keys"
d run --rm --network none --user "$(id -u):$(id -g)" -v "$WORK/bin/pit.test:/pit/pit.test:ro" -v "$WORK/keys:/keys" \
  -e PIT_ROLE=keygen -e PIT_KEYGEN_OUT=/keys --entrypoint /pit/pit.test "$ALPINE_IMAGE" >/dev/null
MANIFEST_PUBKEY=$(cat "$WORK/keys/manifest_pubkey"); RECOVERY_RECIPIENT=$(cat "$WORK/keys/recovery_recipient")
cp "$WORK/keys/manifest_signing_key" "$WORK/secrets/manifest_signing_key"
KEY_GRACE=${PIT_KEY_GRACE:-20s}

log "gốc tạm $IT_ROOT: tenants/ (root 0755), backups/tenants/ (0700), run/ (root:$WORKER_GID 0750), token agent/edge (root:$WORKER_GID 0440), allowlist, khóa ký manifest (root 0400)"
( umask 077
  token() { python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40)), end="")'; }
  token > "$WORK/secrets/agent_token"
  token > "$WORK/secrets/edge_token"
  printf '# allowlist của lần chạy (versions.lock [images.mg-headscale])\n%s\n' "$HS_IMAGE" > "$WORK/secrets/allowlist"
  PGPW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf 'POSTGRES_PASSWORD=%s\n' "$PGPW" > "$WORK/secrets/pg-server.env"
  printf 'MG_TEST_PG_ADMIN_URL=postgres://postgres:%s@%s-pg:5432/postgres?sslmode=disable\nMG_TEST_PG_REQUIRED=1\n' "$PGPW" "$P" \
    > "$WORK/secrets/pg.env" )
d run --rm --network none -v "$IT_ROOT:$IT_ROOT" -v "$WORK/secrets:/s:ro" "$ALPINE_IMAGE" sh -ec "
  cd '$IT_ROOT'
  install -d -o 0 -g 0 -m 0755 tenants cfg
  install -d -o 0 -g 0 -m 0700 backups backups/tenants
  install -d -o 0 -g $WORKER_GID -m 0750 run
  install -o 0 -g $WORKER_GID -m 0440 /s/agent_token cfg/agent_token
  install -o 0 -g $WORKER_GID -m 0440 /s/edge_token cfg/edge_token
  install -o 0 -g 0 -m 0644 /s/allowlist cfg/allowlist
  install -o 0 -g 0 -m 0400 /s/manifest_signing_key cfg/manifest_signing_key"
mkdir -p "$OUT/workers" && chmod 0777 "$OUT/workers"   # logs of the worker processes (UID 65532; no secret — checked)

log "network $P-net ($CTL), PostgreSQL $PG_IMAGE"
d network create --driver bridge --subnet "$CTL" --label "pit.run=$P" "$P-net" >/dev/null
d run -d --name "$P-pg" --network "$P-net" --label "pit.run=$P" --env-file "$WORK/secrets/pg-server.env" "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  d exec "$P-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
  sleep 1
done
d exec "$P-pg" pg_isready -h 127.0.0.1 -U postgres >/dev/null || { d logs --tail 30 "$P-pg"; exit 1; }

log "Host Agent $IMAGE (như compose mg-agent; pool $POOL, run_uid $RUN_UIDS, edge $P-edge)"
d run -d --name "$P-agent" --label "pit.run=$P" --network none --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --security-opt no-new-privileges --user 0:0 \
  --pids-limit 256 --memory 512m -v /var/run/docker.sock:/var/run/docker.sock -v "$IT_ROOT:$IT_ROOT" \
  -e MG_ENV=ci -e MG_LOG_LEVEL=info -e "MG_BASE_DOMAIN=$BASE_DOMAIN" -e MG_AGENT_DRIVER=compose \
  -e "MG_AGENT_SOCKET=$IT_ROOT/run/agent.sock" -e "MG_AGENT_SOCKET_GID=$WORKER_GID" -e "MG_AGENT_PEER_UIDS=$WORKER_UID" \
  -e "MG_AGENT_TOKEN_FILE=$IT_ROOT/cfg/agent_token" -e "MG_AGENT_IMAGE_ALLOWLIST_FILE=$IT_ROOT/cfg/allowlist" \
  -e "MG_AGENT_TENANTS_DIR=$IT_ROOT/tenants" -e "MG_AGENT_BACKUPS_DIR=$IT_ROOT/backups/tenants" \
  -e "MG_AGENT_RUN_UID_RANGE=$RUN_UIDS" -e "MG_AGENT_TENANT_NET_POOL=$POOL" -e "MG_AGENT_PUBLIC_ENTRY_IPV4=$PUBLIC_IPV4" \
  -e "MG_AGENT_EDGE_CONTAINER=$P-edge" -e "MG_AGENT_EDGE_NETWORK=$P-net" -e MG_AGENT_EDGE_SUPERVISOR_INTERVAL=5s \
  -e "MG_AGENT_HELPER_IMAGE=$HELPER_IMAGE" -e MG_AGENT_COMPOSE_BIN=/usr/local/bin/docker-compose \
  -e "MG_AGENT_MANIFEST_SIGNING_KEY_FILE=$IT_ROOT/cfg/manifest_signing_key" -e "MG_AGENT_BACKUP_RECOVERY_RECIPIENT=$RECOVERY_RECIPIENT" \
  -e "MG_BACKUP_MANIFEST_PUBKEY=$MANIFEST_PUBKEY" \
  -e DOCKER_HOST=unix:///var/run/docker.sock -e DOCKER_CONFIG=/tmp/docker "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  d exec "$P-agent" /usr/local/bin/meshguard-agent healthcheck >/dev/null 2>&1 && break
  sleep 1
done
d exec "$P-agent" /usr/local/bin/meshguard-agent healthcheck >/dev/null || { d logs --tail 40 "$P-agent"; exit 1; }

log "edge thử $P-edge (admin :8081, public :8080; gw_priority 1 trên $P-net)"
d run -d --name "$P-edge" --label "pit.run=$P" --network "name=$P-net,gw-priority=1" --user "$WORKER_UID:$WORKER_GID" \
  --read-only --cap-drop ALL --security-opt no-new-privileges -v "$WORK/bin/pit.test:/pit/pit.test:ro" \
  -v "$IT_ROOT/cfg/edge_token:/run/pit/edge_token:ro" -e PIT_ROLE=edge -e PIT_EDGE_TOKEN_FILE=/run/pit/edge_token \
  -e "PIT_BASE_DOMAIN=$BASE_DOMAIN" --entrypoint /pit/pit.test "$ALPINE_IMAGE" >/dev/null
sleep 1
[ "$(d inspect -f '{{.State.Running}}' "$P-edge")" = true ] || { d logs "$P-edge"; exit 1; }

SOCK_GID=$(stat -c %g /var/run/docker.sock)
log "harness $P-run (UID $WORKER_UID, nhóm $WORKER_GID + $SOCK_GID của Docker socket — chỉ đọc), gốc tạm chỉ đọc"
d create --name "$P-run" --label "pit.run=$P" --network "$P-net" --user "$WORKER_UID:$WORKER_UID" --group-add "$WORKER_GID" \
  --group-add "$SOCK_GID" --read-only --tmpfs /tmp:size=512m,mode=1777 --cap-drop ALL --security-opt no-new-privileges \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$IT_ROOT:$IT_ROOT:ro" -v "$WORK/bin/pit.test:/pit/pit.test:ro" \
  -v "$OUT/workers:/pit/workers" -e PIT_LOG_DIR=/pit/workers --env-file "$WORK/secrets/pg.env" -e TMPDIR=/tmp -e HOME=/tmp -e "PIT_PREFIX=$P" -e "PIT_ROOT=$IT_ROOT" \
  -e "PIT_POOL=$POOL" -e "PIT_RUN_UIDS=$RUN_UIDS" -e "PIT_PUBLIC_IPV4=$PUBLIC_IPV4" -e "PIT_BASE_DOMAIN=$BASE_DOMAIN" \
  -e "PIT_HS_DIGEST=$HS_DIGEST" -e "PIT_HS_VERSION=$HS_VERSION" -e "PIT_EDGE=$P-edge" -e "PIT_EDGE_NETWORK=$P-net" \
  -e "PIT_EDGE_ADMIN=http://$P-edge:8081" -e "PIT_EDGE_PUBLIC=$P-edge:8080" -e "PIT_PG_CONTAINER=$P-pg" \
  -e "PIT_MANIFEST_PUBKEY=$MANIFEST_PUBKEY" -e "PIT_KEY_GRACE=$KEY_GRACE" \
  --entrypoint /pit/pit.test "$ALPINE_IMAGE" -test.v -test.count=1 -test.timeout=70m \
  -test.run "${PIT_RUN:-^(TestBackfillAdoptedInstance|TestProvisioningFaultInjection|TestPostRestoreReconcile)\$}" >/dev/null
log "chạy các ca E2E-84 (P3-T14b: backfill instance dựng tay + adopt), E2E-48…E2E-51 (P3-T07), E2E-73…E2E-75 + deprovision cuối lần chạy (P3-T09) và E2E-72 (P3-T17)…"
rc=0
d start -a "$P-run" > "$OUT/pit.log" 2>&1 || rc=$?
d logs "$P-agent" > "$OUT/agent.log" 2>&1 || true
d logs "$P-edge" > "$OUT/edge.log" 2>&1 || true

# what the run left on the host, BEFORE the infrastructure of the harness goes: no tenant container, network or helper
{ d ps -a --format '{{.Names}} {{.State}}' | grep -E "^(mg-hs-$P-|mg-helper-$P-)" || true
  d network ls --format '{{.Name}}' | grep -E "^mg-t-$P-" || true
  d inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$P-edge" | tr ' ' '\n' | grep -E "^mg-t-$P-" | sed 's/^/edge→/' || true
} > "$OUT/leftovers.txt"
dirs=$(d run --rm --network none -v "$IT_ROOT/tenants:/t:ro" "$ALPINE_IMAGE" ls -A /t | wc -l)
# backup cuối của các tenant đã deprovision: archive (+ manifest ký) giữ lại theo retention
archives=$(d run --rm --network none -v "$IT_ROOT/backups:/b:ro" "$ALPINE_IMAGE" sh -c 'find /b/tenants -name "*.tar.age" | wc -l')
manifests=$(d run --rm --network none -v "$IT_ROOT/backups:/b:ro" "$ALPINE_IMAGE" sh -c 'find /b/tenants -name "*.manifest.sig" | wc -l')
keys_in_agent_log=$(grep -c 'hskey-api-' "$OUT/agent.log" || true)
for c in "$P-run" "$P-edge" "$P-agent" "$P-pg"; do d rm -f "$c" >/dev/null 2>&1 || true; done
d network rm "$P-net" >/dev/null 2>&1 || true
d run --rm --network none -v "$IT_ROOT:/r" "$ALPINE_IMAGE" sh -c 'rm -rf /r/* /r/.[!.]*' >/dev/null 2>&1 || true
rmdir "$IT_ROOT" || { log "gốc tạm $IT_ROOT không xóa được"; rc=1; }
snapshot > "$OUT/after.txt"

grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS|FAIL|ok)|cases_test.go:|backfill_test.go:|postrestore_test.go:|summary of the cases|^ +E2E-' "$OUT/pit.log" | grep -v '=== RUN' || true
grep -A 7 'E2E-72 summary:' "$OUT/pit.log" || true
grep -E "E2E-84 (summary|refused|backfill:)" "$OUT/pit.log" || true
log "còn lại sau các ca (trước khi gỡ hạ tầng của harness): $(grep -c . "$OUT/leftovers.txt" || true) đối tượng Docker; $dirs thư mục instance (của TestPostRestoreReconcile, gỡ với KEEP — run.sh xóa; TestProvisioningFaultInjection tự kiểm 0 thư mục sau deprovision cuối lần chạy); $archives archive backup cuối ($manifests manifest ký) giữ theo retention; $keys_in_agent_log dòng log agent có API key"
[ -s "$OUT/leftovers.txt" ] && { log "TÀI NGUYÊN CÒN LẠI:"; cat "$OUT/leftovers.txt"; rc=1; }
[ "$keys_in_agent_log" = 0 ] || { log "API key trong log agent"; rc=1; }
if ! diff -u "$OUT/before.txt" "$OUT/after.txt" > "$OUT/snapshot.diff"; then
  log "SNAPSHOT KHÁC (đối tượng của lần chạy trước và sau):"; cat "$OUT/snapshot.diff"; rc=1
else
  log "snapshot trước = sau: $(grep -c . "$OUT/before.txt" || true) dòng (đối tượng mang tiền tố $P)"
fi
if [ "$rc" = 0 ] && [ -z "${PIT_RUN:-}" ] && grep -q '^--- PASS: TestProvisioningFaultInjection' "$OUT/pit.log" &&
  grep -q '^--- PASS: TestPostRestoreReconcile' "$OUT/pit.log" && grep -q '^--- PASS: TestBackfillAdoptedInstance' "$OUT/pit.log"; then
  log "PROVISIONING FAULT INJECTION: PASS"
else
  log "PROVISIONING FAULT INJECTION: FAIL (log: $OUT/pit.log)"; tail -80 "$OUT/pit.log"; exit 1
fi
