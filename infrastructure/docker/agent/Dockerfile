# Image của Host Agent (P3-T01; master §11.1, §14.4, ADR-05): `meshguard-agent` — thành phần DUY NHẤT có Docker socket.
# Chạy root (USER 0:0) vì phải chown thư mục sang run_uid và đi qua thư mục 0700 của tenant; compose của agent (P3-T02)
# thả mọi capability trừ CHOWN, FOWNER, DAC_OVERRIDE, rootfs chỉ-đọc, no-new-privileges, network_mode: none.
# P3-T01 chỉ có binary Go (giao thức + kiểm tra + healthcheck); CLI docker/compose, sqlite3 (≥ 3.51.3 — §17.1) và age
# được thêm ở P3-T02/P3-T11 khi driver cần — lúc đó base có thể phải đổi (CLI cần libc hoặc bản tĩnh).
# Base pin theo digest (versions.lock [images.golang], [images.distroless-static]); module Go kiểm bằng go.sum.
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
# APP: cùng tham số với workflow images (chỉ nhận agent)
ARG APP=agent
ARG VERSION=dev
ARG COMMIT=unknown
RUN test "${APP}" = agent \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Version=${VERSION} -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Commit=${COMMIT}" \
      -o /out/meshguard-agent ./apps/agent

FROM ${RUNTIME}
COPY --from=build /out/meshguard-agent /usr/local/bin/meshguard-agent
USER 0:0
# Không EXPOSE: agent chỉ nghe Unix socket /run/meshguard/agent.sock (không TCP).
ENTRYPOINT ["/usr/local/bin/meshguard-agent"]
