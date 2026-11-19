#!/bin/bash
# dep4 — image cho host lồng: (1) image pin (digest của versions.lock) có sẵn trong cache của VM 110 ⇒ save | load +
# tag <repo>:dep4 (digest giữ nguyên, tham chiếu name@sha256 phân giải tại chỗ); (2) image công khai còn thiếu ⇒ pull theo
# digest bên trong host lồng; (3) image tự build ⇒ build từ cây trong host lồng (mục dưới, nền).
set -euo pipefail
O="sudo -n docker"
N="sudo -n docker exec -i dep4-host docker"
W=$HOME/dep4
lock() { python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))["images"][sys.argv[2]]
print(d["image"] + "@" + d["index"])' "$SRC/new/versions.lock" "$1"; }
SRC=$W/root/rootdir/src; sudo mkdir -p "$SRC/new" "$SRC/old" "$SRC/v9"
[ -f "$SRC/new/versions.lock" ] || sudo tar -xzf "$W/in/new.tgz" -C "$SRC/new"
[ -f "$SRC/old/versions.lock" ] || sudo tar -xzf "$W/in/old.tgz" -C "$SRC/old"
[ -f "$SRC/v9/versions.lock" ] || sudo tar -xzf "$W/in/v9.tgz" -C "$SRC/v9"
for k in mg-edge mg-stund mg-idp mg-headscale headscale postgres alpine golang node distroless-static prometheus alertmanager; do
  ref=$(lock "$k"); repo=${ref%@*}; dg=${ref#*@}
  if $N image inspect "$ref" >/dev/null 2>&1; then echo "có sẵn $k"; continue; fi
  if $O image inspect "$ref" >/dev/null 2>&1; then
    $O save "$ref" | $N load >/dev/null && $N tag "$dg" "$repo:dep4" && echo "load $k"
  else
    echo "THIẾU trong cache VM: $k ($ref) — pull trong host lồng"; $N pull -q "$ref" >/dev/null && echo "pull $k"
  fi
done
for k in crowdsec caddy-builder distroless-base-nonroot; do
  ref=$(lock "$k")
  $N image inspect "$ref" >/dev/null 2>&1 || { $N pull -q "$ref" >/dev/null && echo "pull $k"; }
done
$N images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort
