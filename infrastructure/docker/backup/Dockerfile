# Image backup (P2-T03a, P2-T05b; §14.4, §17.1): meshguard-backup (apps/backup) + pg_dump/pg_dumpall/pg_restore 18.7
# + age. Một image cho ba dịch vụ của project mg-backup (pg-backup, idp-backup, edge-backup).
#   - pg_dump/pg_dumpall/pg_restore: chép từ ĐÚNG image postgres đang chạy (versions.lock [images.postgres], 18.7-trixie)
#     ⇒ cùng phiên bản với server. Thư viện của chúng mà base chưa có được chép cùng bản ghi dpkg (status.d) và file
#     copyright của gói chứa chúng, để SBOM (syft) và grype thấy đúng gói/phiên bản.
#   - age: build lại từ mã nguồn pin (versions.lock [sources.age]) bằng đúng công thức của
#     infrastructure/host/key-ceremony/build-age.sh (cùng module bọc age-build/ với x/crypto đã vá, cùng image golang,
#     cùng cờ) ⇒ sha256 phải trùng versions.lock — kiểm ngay trong build (khác ⇒ build fail).
#   - meshguard-backup: Go tĩnh, thư viện chuẩn + internal/kit (module ngoài duy nhất: google/uuid qua
#     internal/kit/requestid — tải qua proxy, kiểm bằng go.sum; -mod=readonly).
# Runtime: distroless base-debian13 nonroot (versions.lock [images.distroless-base-nonroot]; glibc, libssl3t64, zlib1g,
# libzstd1 của Debian 13 — cùng bản phát hành với image postgres 18.7-trixie). Không trình quản lý gói, không
# coreutils. Có MỘT shell: dash làm /bin/sh, vì pg_dumpall gọi popen("pg_dump -V") (find_other_exec) để kiểm pg_dump
# cùng thư mục — thiếu /bin/sh thì pg_dumpall --globals-only thất bại (đối chứng trong tests/backup/drill.sh). Không
# bash, perl hay công cụ nào khác.
# Chạy non-root 10007:20007 (UID riêng của dịch vụ backup, nhóm mg-sec-backup — versions.lock [ids]); compose đặt
# rootfs chỉ-đọc, cap_drop ALL, no-new-privileges.
#   docker build -f infrastructure/docker/backup/Dockerfile --build-arg VERSION=… --build-arg COMMIT=… .
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG POSTGRES=docker.io/library/postgres:18.7-trixie@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc
ARG RUNTIME=gcr.io/distroless/base-debian13:nonroot@sha256:a08d9054afbaf1af9b90fd02cdc7b32236319b5376d374505a41548d42b0c5db

FROM ${RUNTIME} AS runtime-base

# ---------------------------------------------------------------- age (công thức của build-age.sh)
# Module bọc infrastructure/host/key-ceremony/age-build (go.mod/go.sum: filippo.io/age + golang.org/x/crypto v0.56.0 —
# GO-2026-6354/6355; P3-T11a), -mod=readonly; -X main.Version ⇒ `age --version` = v1.3.2.
FROM ${GOLANG} AS age
ARG AGE_MODULE=filippo.io/age
ARG AGE_VERSION=v1.3.2
ARG AGE_SHA256=571136ee8b7cbb0f67cd8ddd2e46ed834b933c62d59500b631a82af6c627e44d
ENV HOME=/tmp CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -mod=readonly" \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE= \
    GOMODCACHE=/tmp/modcache GOCACHE=/tmp/gocache
WORKDIR /src
COPY infrastructure/host/key-ceremony/age-build/go.mod infrastructure/host/key-ceremony/age-build/go.sum ./
RUN test "$(go list -m "${AGE_MODULE}")" = "${AGE_MODULE} ${AGE_VERSION}" \
 && go build -ldflags "-X main.Version=${AGE_VERSION}" -o /out/age "${AGE_MODULE}/cmd/age" \
 && echo "${AGE_SHA256}  /out/age" | sha256sum -c - \
 && test "$(/out/age --version)" = "${AGE_VERSION}"

# ---------------------------------------------------------------- meshguard-backup
FROM ${GOLANG} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
COPY apps/backup ./apps/backup
COPY internal/kit ./internal/kit
ARG APP=backup
ARG VERSION=dev
ARG COMMIT=unknown
RUN test "${APP}" = backup \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Version=${VERSION} -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Commit=${COMMIT}" \
      -o /out/meshguard-backup ./apps/backup

# ---------------------------------------------------------------- công cụ PostgreSQL + thư viện + dash
FROM ${POSTGRES} AS pg
COPY --from=runtime-base /var/lib/dpkg/status.d /base-status.d
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN out=/rootfs; bin=/usr/lib/postgresql/18/bin; \
    mkdir -p "$out/usr/local/bin" "$out/usr/bin" "$out/var/lib/dpkg/status.d" "$out/usr/share/doc"; \
    for b in pg_dump pg_dumpall pg_restore; do cp "$bin/$b" "$out/usr/local/bin/$b"; done; \
    cp /usr/bin/dash "$out/usr/bin/dash"; ln -s dash "$out/usr/bin/sh"; \
    progs=("$bin/pg_dump" "$bin/pg_dumpall" "$bin/pg_restore" /usr/bin/dash); \
    mapfile -t libs < <(for p in "${progs[@]}"; do ldd "$p"; done | awk '$2 == "=>" && $3 ~ /^\// {print $3}' | sort -u); \
    declare -A pkgs; \
    for f in "${progs[@]}" "${libs[@]}"; do \
      real=$(readlink -f "$f"); \
      pkg=$(dpkg -S "$real" | head -n1 | cut -d: -f1); \
      test -n "$pkg"; \
      if [ -e "/base-status.d/$pkg" ]; then echo "base có sẵn: $pkg ($real)"; continue; fi; \
      pkgs[$pkg]=1; \
      case "$f" in "$bin"/*|/usr/bin/dash) continue ;; esac; \
      mkdir -p "$out$(dirname "$real")"; cp "$real" "$out$real"; \
      name=$(basename "$f"); \
      if [ "$name" != "$(basename "$real")" ]; then ln -sf "$(basename "$real")" "$out/usr/lib/x86_64-linux-gnu/$name"; fi; \
      echo "chép: $pkg $real"; \
    done; \
    for p in "${!pkgs[@]}"; do \
      dpkg-query -s "$p" > "$out/var/lib/dpkg/status.d/$p"; \
      if [ -f "/usr/share/doc/$p/copyright" ]; then mkdir -p "$out/usr/share/doc/$p"; cp "/usr/share/doc/$p/copyright" "$out/usr/share/doc/$p/"; fi; \
      echo "gói: $p $(dpkg-query -W -f='${Version}' "$p")"; \
    done; \
    "$bin/pg_dump" --version | grep -q '^pg_dump (PostgreSQL) 18\.7 '

# ---------------------------------------------------------------- runtime
FROM ${RUNTIME}
COPY --from=pg /rootfs/ /
COPY --from=age /out/age /usr/local/bin/age
COPY --from=build /out/meshguard-backup /usr/local/bin/meshguard-backup
RUN ["/usr/local/bin/pg_dump", "--version"]
RUN ["/usr/local/bin/pg_restore", "--version"]
RUN ["/usr/local/bin/age", "--version"]
RUN ["/usr/local/bin/meshguard-backup", "version"]
USER 10007:20007
ENTRYPOINT ["/usr/local/bin/meshguard-backup"]
CMD ["run"]
