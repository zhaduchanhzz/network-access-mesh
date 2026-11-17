# Headscale v0.29.7 + bản vá bảo mật của MeshGuard (P2-T10a, ADR-02 sửa đổi 2026-11-17): sửa V-26 — `AuthRegister`
# với Auth ID của phiên SSH-check làm Headscale panic và thoát — và recover panic trên cả hai gRPC server.
#   docker build -t <tag> infrastructure/docker/headscale
# Nguồn: tarball của đúng commit c9cf210b (tag v0.29.7) từ GitHub, kiểm sha256 và commit ghi trong archive; bản vá áp theo
# patches/series (kiểm sha256 từng file, `git apply --check` trước, lệch một dòng là dừng). Unit test của các package
# bị vá chạy trong lúc build. Mọi giá trị pin trùng versions.lock [sources.headscale] (CI images kiểm sự trùng khớp).
#
# Phiên bản: Headscale lấy version từ thông tin VCS mà Go ghi vào binary (debug.ReadBuildInfo — không có biến -X nào;
# `-X main.version` của goreleaser không trỏ tới biến nào). Build trong một repo git dựng từ tarball, mỗi bản vá là
# một commit, tag v0.29.7 đặt ở commit cuối ⇒ version = "v0.29.7" (adapter chỉ nhận X.Y.Z; DB version check RT-10
# của Headscale cùng minor), commit = HEADSCALE_PATCHED_COMMIT (tất định: metadata cố định) — dấu hiệu bản vá trong
# `headscale version` và `GET /version`; mức vá còn ở label io.meshguard.headscale.*.
#
# Runtime giống image chính thức (ko): distroless base-debian13, /ko-app/headscale, PATH có /ko-app (healthcheck
# `headscale health` của compose tenant), cùng ENV, không CMD. Khác: base mới hơn base của image chính thức
# (sha256:0a904783…: zlib1g còn CVE-2026-76844, CVE-2026-85091 — High), Go 1.27.4 thay vì 1.27.3, -trimpath, user mặc
# định 65532 thay vì 0 (compose tenant luôn đặt user = run_uid riêng của instance).
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/base-debian13:latest@sha256:0e48b9bcd868bce9fa872cee10b52961d9e32677823da4bf68eefb44f38e7b9d

FROM ${GOLANG} AS build
ARG HEADSCALE_VERSION=v0.29.7
ARG HEADSCALE_COMMIT=c9cf210b8bc84d13177e18b91f555788a44b47b6
ARG HEADSCALE_COMMIT_TIME=2026-10-30T09:33:17Z
ARG HEADSCALE_TARBALL_SHA256=e0fd854b6cc5b94237230c4a9429fe187e3859af9449417e3152bea1648908f2
ARG HEADSCALE_PATCHED_COMMIT=f9cc62beaa49c207839c67a75e89fb7c7c82ed97
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
    GIT_COMMITTER_NAME=MeshGuard GIT_COMMITTER_EMAIL=noreply@meshguard.invalid
COPY patches/ /patches/
RUN cd /patches && sha256sum -c series \
 && curl -fsSL --retry 3 -o /tmp/headscale.tar.gz \
      "https://codeload.github.com/juanfont/headscale/tar.gz/${HEADSCALE_COMMIT}" \
 && echo "${HEADSCALE_TARBALL_SHA256}  /tmp/headscale.tar.gz" | sha256sum -c - \
 && test "$(gzip -dc /tmp/headscale.tar.gz | git get-tar-commit-id)" = "${HEADSCALE_COMMIT}" \
 && mkdir /src && tar -xzf /tmp/headscale.tar.gz -C /src --strip-components=1 --no-same-owner && rm /tmp/headscale.tar.gz \
 && cd /src && git init -q -b upstream \
 && git add -A \
 && GIT_AUTHOR_NAME=upstream GIT_AUTHOR_EMAIL=upstream@headscale.invalid \
    GIT_AUTHOR_DATE="${HEADSCALE_COMMIT_TIME}" GIT_COMMITTER_DATE="${HEADSCALE_COMMIT_TIME}" \
    git commit -q -m "headscale ${HEADSCALE_VERSION} (${HEADSCALE_COMMIT}, tarball sha256 ${HEADSCALE_TARBALL_SHA256})" \
 && for p in $(awk '{print $2}' /patches/series); do \
      git apply --check "/patches/${p}" && git am -q --committer-date-is-author-date "/patches/${p}" || exit 1; \
    done \
 && git tag "${HEADSCALE_VERSION}" \
 && test -z "$(git status --porcelain)" \
 && echo "patched commit: $(git rev-parse HEAD)" \
 && test "$(git rev-parse HEAD)" = "${HEADSCALE_PATCHED_COMMIT}"
WORKDIR /src
RUN go mod download && go mod verify
# Unit test của các package bị vá (hscontrol, hscontrol/state) — gồm test của chính bản vá.
RUN go test -count=1 ./hscontrol/ ./hscontrol/state/
RUN go build -trimpath -ldflags="-s -w" -o /out/headscale ./cmd/headscale \
 && go version -m /out/headscale > /out/buildinfo.txt \
 && grep -Eq "^[[:space:]]mod[[:space:]]+github.com/juanfont/headscale[[:space:]]+${HEADSCALE_VERSION}[[:space:]]*$" /out/buildinfo.txt \
 && grep -q "vcs.revision=${HEADSCALE_PATCHED_COMMIT}" /out/buildinfo.txt \
 && grep -q 'vcs.modified=false' /out/buildinfo.txt \
 && grep -q -- '-trimpath=true' /out/buildinfo.txt \
 && grep -q 'CGO_ENABLED=0' /out/buildinfo.txt \
 && /out/headscale version -o json > /out/version.json \
 && grep -q "\"version\": *\"${HEADSCALE_VERSION}\"" /out/version.json \
 && grep -q "\"commit\": *\"${HEADSCALE_PATCHED_COMMIT}\"" /out/version.json \
 && chmod 0555 /out/headscale

FROM ${RUNTIME}
ARG HEADSCALE_VERSION=v0.29.7
ARG HEADSCALE_COMMIT=c9cf210b8bc84d13177e18b91f555788a44b47b6
ARG HEADSCALE_PATCHED_COMMIT=f9cc62beaa49c207839c67a75e89fb7c7c82ed97
ARG HEADSCALE_PATCH_LEVEL=mg.1
COPY --from=build /out/headscale /ko-app/headscale
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/ko-app \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    KO_DATA_PATH=/var/run/ko
LABEL io.meshguard.headscale.upstream="github.com/juanfont/headscale ${HEADSCALE_VERSION} (${HEADSCALE_COMMIT})" \
      io.meshguard.headscale.patch-level="${HEADSCALE_PATCH_LEVEL}" \
      io.meshguard.headscale.patched-commit="${HEADSCALE_PATCHED_COMMIT}" \
      org.opencontainers.image.version="${HEADSCALE_VERSION}+${HEADSCALE_PATCH_LEVEL}" \
      org.opencontainers.image.licenses="BSD-3-Clause"
WORKDIR /
USER 65532:65532
ENTRYPOINT ["/ko-app/headscale"]
