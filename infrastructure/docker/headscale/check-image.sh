#!/usr/bin/env bash
# Kiểm nội dung image Headscale vá (P2-T10a) — bước "Kiểm nội dung image" của workflow images, chạy được cả trên VM:
#   bash infrastructure/docker/headscale/check-image.sh <image>                 # từ gốc repo
#   DOCKER="sudo docker" HSCI_PREFIX=p2t10a-hsci bash …/check-image.sh <image>  # docker cần sudo, tiền tố riêng
# Kiểm: versions.lock [sources.headscale] khớp Dockerfile + patches/series; label dấu bản vá; `headscale version` giữ
# v0.29.7 và báo commit của bản vá; chạy `serve` như compose tenant (user riêng không phải root, rootfs chỉ đọc,
# cap_drop ALL, tmpfs /var/run/headscale) và `headscale health` qua PATH như healthcheck của compose.
set -euo pipefail
IMG=${1:?usage: check-image.sh <image>}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="$ROOT/infrastructure/docker/headscale"
read -r -a DOCKER_CMD <<< "${DOCKER:-docker}"
d() { "${DOCKER_CMD[@]}" "$@"; }
P=${HSCI_PREFIX:-hsci}
RUN_UID=30001
WORK=$(mktemp -d -t hsci.XXXXXX)
cleanup() { d rm -f "$P-smoke" >/dev/null 2>&1 || true; d volume rm -f "$P-data" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

python3 - "$ROOT/versions.lock" "$HERE/Dockerfile" "$HERE/patches/series" <<'PY'
import re, sys, tomllib
lock = tomllib.load(open(sys.argv[1], "rb"))["sources"]["headscale"]
df = open(sys.argv[2], encoding="utf-8").read()
def arg(name):
    values = set(re.findall(rf"^ARG {name}=(\S+)$", df, re.M))
    assert len(values) == 1, f"ARG {name}: {values}"
    return values.pop()
for name, key in [("HEADSCALE_VERSION", "version"), ("HEADSCALE_COMMIT", "commit"), ("HEADSCALE_COMMIT_TIME", "commit_time"),
                  ("HEADSCALE_TARBALL_SHA256", "tarball_sha256"), ("HEADSCALE_PATCHED_COMMIT", "patched_commit"),
                  ("HEADSCALE_PATCH_LEVEL", "patch_level")]:
    assert arg(name) == lock[key], f"Dockerfile ARG {name}={arg(name)} ≠ versions.lock {key}={lock[key]}"
series = {name: digest for digest, name in (line.split() for line in open(sys.argv[3], encoding="utf-8") if line.strip())}
assert series == lock["patches"], f"patches/series {series} ≠ versions.lock patches {lock['patches']}"
print(f"versions.lock [sources.headscale] khớp Dockerfile và patches/series ({len(series)} bản vá)")
PY
read -r UPSTREAM PATCHED LEVEL < <(python3 -c 'import sys, tomllib; h = tomllib.load(open(sys.argv[1], "rb"))["sources"]["headscale"]
print(h["commit"], h["patched_commit"], h["patch_level"])' "$ROOT/versions.lock")

user=$(d image inspect -f '{{.Config.User}}' "$IMG")
entry=$(d image inspect -f '{{json .Config.Entrypoint}}' "$IMG")
label=$(d image inspect -f '{{index .Config.Labels "io.meshguard.headscale.patched-commit"}} {{index .Config.Labels "io.meshguard.headscale.patch-level"}}' "$IMG")
echo "user=$user entrypoint=$entry label=$label"
[ "$user" = "65532:65532" ] && [ "$entry" = '["/ko-app/headscale"]' ] && [ "$label" = "$PATCHED $LEVEL" ] && [ "$PATCHED" != "$UPSTREAM" ]

# `headscale version`: version giữ v0.29.7 (adapter chỉ nhận X.Y.Z; DB version check RT-10), commit = dấu bản vá
d run --rm --network none --read-only --cap-drop ALL --user "$RUN_UID:$RUN_UID" "$IMG" version | tee "$WORK/version.txt"
grep -qx 'headscale version v0.29.7' "$WORK/version.txt"
grep -qx "commit: $PATCHED" "$WORK/version.txt"

# serve như compose tenant (infrastructure/headscale/templates/compose.tenant.yaml.tmpl), config render thật
python3 "$ROOT/tools/render_instance.py" "$ROOT/tests/integration/headscale/testdata/params.json" "$WORK/render" >/dev/null 2>&1
chmod -R a+rX "$WORK/render" && chmod 0755 "$WORK"
d volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt "o=size=32m,uid=$RUN_UID,gid=$RUN_UID,mode=0700" "$P-data" >/dev/null
d run -d --name "$P-smoke" --network none --user "$RUN_UID:$RUN_UID" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs "/var/run/headscale:size=1m,mode=0700,uid=$RUN_UID,gid=$RUN_UID" \
  -v "$WORK/render/config:/etc/headscale:ro" -v "$WORK/render/records:/etc/headscale-records:ro" \
  -v "$P-data:/var/lib/headscale" "$IMG" serve >/dev/null
ok=""
for _ in $(seq 1 60); do
  if d exec "$P-smoke" headscale health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { d logs --tail 40 "$P-smoke"; echo "headscale health không đạt"; exit 1; }
d exec "$P-smoke" headscale health
uids=$(d top "$P-smoke" -eo pid,uid | awk 'NR > 1 {print $2}' | sort -u | tr '\n' ' ')
ro=$(d inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$P-smoke")
echo "tiến trình trong container chạy với uid: $uids; rootfs chỉ đọc: $ro"
[ "$uids" = "$RUN_UID " ] && [ "$ro" = true ]
echo "headscale image OK: v0.29.7, commit $PATCHED ($LEVEL), non-root, read-only"
