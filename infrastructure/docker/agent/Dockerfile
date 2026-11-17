# Image của Host Agent (P3-T01, P3-T02; master §11.1, §14.4, ADR-05): `meshguard-agent` — thành phần DUY NHẤT có Docker
# socket. Chạy root (USER 0:0) vì phải chown thư mục sang run_uid và đi qua thư mục 0700 của tenant; compose của agent
# (infrastructure/compose/compose.agent.yaml.tmpl) thả mọi capability trừ CHOWN, FOWNER, DAC_OVERRIDE, rootfs chỉ-đọc,
# no-new-privileges, network_mode: none.
# P3-T02 thêm Docker Compose (binary độc lập `docker-compose`, build lại từ mã nguồn bản phát hành — cùng chương trình
# với CLI plugin `docker compose`): compose driver chạy `docker-compose --project-name mg-t-<slug> …`; trạng thái/inventory/
# network đi qua Docker Engine API (moby client trong binary Go) nên KHÔNG cần CLI `docker`. Binary compose build tĩnh
# (CGO tắt) ⇒ giữ base distroless static, không đổi base. sqlite3 (≥ 3.51.3 — §17.1) và age thêm ở P3-T11.
# Base và công cụ pin theo digest/SHA-256 (versions.lock [images.golang], [images.distroless-static],
# [sources.docker-compose]); module Go kiểm bằng go.sum; template instance nhúng vào binary (infrastructure/headscale/templates).
#   docker build -f infrastructure/docker/agent/Dockerfile --build-arg VERSION=… --build-arg COMMIT=… .
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GOLANG} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY api/agent ./api/agent
COPY apps/agent ./apps/agent
COPY internal ./internal
COPY infrastructure/headscale/templates ./infrastructure/headscale/templates
# APP: cùng tham số với workflow images (chỉ nhận agent)
ARG APP=agent
ARG VERSION=dev
ARG COMMIT=unknown
RUN test "${APP}" = agent \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Version=${VERSION} -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Commit=${COMMIT}" \
      -o /out/meshguard-agent ./apps/agent

# Docker Compose — versions.lock [sources.docker-compose]: build lại từ mã nguồn của bản phát hành (module
# github.com/docker/compose/v5, kiểm qua checksum DB của Go) bằng toolchain đã pin, với hai bản vá phụ thuộc mà bản
# phát hành v5.7.0 còn thiếu (grype: High GO-2026-6865 klauspost/compress v1.20.0, GO-2026-6860 x/net v0.60.0;
# govulncheck -mode=binary: GO-2026-6865 + GO-2026-6859 của go1.26.10) — cùng cách của [sources.edge-overrides].
# Build tái lập: sha256 của binary phải trùng build_sha256 (CGO tắt, -trimpath, không VCS stamp).
FROM ${GOLANG} AS compose
ARG COMPOSE_VERSION=v5.7.0
ARG COMPOSE_BUILD_SHA256=0580ba643450f8ca8e254b53886639e816de9805113e731b49a3da6efe1a0363
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN go mod download "github.com/docker/compose/v5@${COMPOSE_VERSION}" \
 && cp -r "$(go env GOMODCACHE)/github.com/docker/compose/v5@${COMPOSE_VERSION}" /tmp/compose \
 && chmod -R u+w /tmp/compose && cd /tmp/compose \
 && go get github.com/klauspost/compress@v1.20.2 golang.org/x/net@v0.62.0 \
 && go build -trimpath -ldflags "-s -w -X github.com/docker/compose/v5/internal.Version=${COMPOSE_VERSION}" -o /docker-compose ./cmd \
 && echo "${COMPOSE_BUILD_SHA256}  /docker-compose" | sha256sum -c - \
 && /docker-compose version | grep -qx "Docker Compose version ${COMPOSE_VERSION}"

FROM ${RUNTIME}
COPY --from=build /out/meshguard-agent /usr/local/bin/meshguard-agent
COPY --from=compose /docker-compose /usr/local/bin/docker-compose
USER 0:0
ENV MG_AGENT_COMPOSE_BIN=/usr/local/bin/docker-compose
# Không EXPOSE: agent chỉ nghe Unix socket /run/meshguard/agent.sock (không TCP).
ENTRYPOINT ["/usr/local/bin/meshguard-agent"]
