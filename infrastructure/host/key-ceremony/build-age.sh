#!/bin/bash
# P2-T04a, P3-T11a — build age và age-keygen (filippo.io/age, phiên bản pin ở versions.lock [sources.age]) từ mã nguồn,
# trong image golang pin theo digest (versions.lock [images.golang]), rồi kiểm sha256 của hai binary với versions.lock.
# Build trong MODULE BỌC age-build/ (go.mod + go.sum cạnh script này): require filippo.io/age cùng bản vá phụ thuộc
# (golang.org/x/crypto v0.56.0 — GO-2026-6354/6355) vì `go install module@version` không ghi đè được phụ thuộc;
# -mod=readonly ⇒ dùng đúng go.sum trong repo. Image backup và agent build lại bằng ĐÚNG công thức này (stage age).
# Chạy trên MÁY BUILD (cần Docker và mạng tới proxy.golang.org) — không chạy trên host staging, không chạy script
# bên thứ ba: Go tải mã qua proxy.golang.org và kiểm từng module với go.sum + checksum DB của Go (sum.golang.org);
# GOFLAGS/GOPROXY/GOSUMDB được đặt tường minh để môi trường của người chạy không tắt được việc kiểm.
# Build tái lập: cùng image + cùng go.mod/go.sum ⇒ cùng sha256 (CGO_ENABLED=0, -trimpath, cache trống mỗi lần;
# -X main.Version=<phiên bản> để `age --version` in v1.3.2 thay cho "(devel)" của module bọc).
#
#   bash infrastructure/host/key-ceremony/build-age.sh <thư mục ra>      # in sha256; exit 1 nếu khác versions.lock
#
# Chép sang host (runbook docs/operations/key-ceremony.md): <repo trên host>/infrastructure/host/key-ceremony/bin/;
# ceremony.sh kiểm lại sha256 trước mỗi lần dùng.
set -euo pipefail
KIT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd -- "$KIT/../../.." && pwd -P)
out=${1:?cú pháp: bash build-age.sh <thư mục ra>}

lock_get() {
  python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for part in sys.argv[2].split("."):
    d = d.get(part) if isinstance(d, dict) else None
v = d.get(sys.argv[3]) if isinstance(d, dict) else None
print("" if v is None else v)' "$REPO/versions.lock" "$1" "$2"
}

ver=$(lock_get sources.age version)
module=$(lock_get sources.age module)
image=$(lock_get images.golang image)@$(lock_get images.golang index)
if [[ ! $ver =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || [ "$module" != filippo.io/age ]; then
  echo "versions.lock [sources.age] không hợp lệ" >&2
  exit 1
fi
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd -P)
echo "build $module@$ver (module bọc $KIT/age-build) trong $image → $out"
# module bọc phải require đúng phiên bản của versions.lock (go list -m đọc go.mod, không tải gì)
docker run --rm --pull missing --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e "GOFLAGS=-trimpath -mod=readonly" \
  -e GOPROXY=https://proxy.golang.org -e GOSUMDB=sum.golang.org -e GONOSUMDB= -e GOPRIVATE= -e GOINSECURE= \
  -e GOMODCACHE=/tmp/modcache -e GOCACHE=/tmp/gocache \
  -v "$KIT/age-build:/src:ro" -v "$out:/out" -w /src "$image" \
  sh -ec 'test "$(go list -m "$1")" = "$1 $2" || { echo "age-build/go.mod không require $1 $2" >&2; exit 1; }
    go build -ldflags "-X main.Version=$2" -o /out/ "$1/cmd/age" "$1/cmd/age-keygen"' sh "$module" "$ver"
fail=0
for b in age age-keygen; do
  want=$(lock_get sources.age "${b//-/_}_linux_amd64_sha256")
  have=$(sha256sum <"$out/$b" | cut -d' ' -f1)
  if [ "$have" = "$want" ]; then echo "OK   $b $("$out/$b" --version) sha256 $have"; else echo "LỖI $b sha256 $have ≠ versions.lock $want"; fail=1; fi
done
exit "$fail"
