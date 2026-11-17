# Image của các tiến trình Go (P2-T01): build một app trong apps/<APP> (api | worker), chạy non-root trên distroless.
# Base pin theo digest (versions.lock); module Go kiểm bằng go.sum (go mod verify). Build context: gốc repo.
#   docker build -f infrastructure/docker/app/Dockerfile --build-arg APP=api --build-arg VERSION=… --build-arg COMMIT=… .
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GOLANG} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY apps ./apps
COPY internal ./internal
# mã sinh của giao thức Host Agent (P3-T01) — worker sẽ import internal/agentclient (P3-T05)
COPY api/agent ./api/agent
# migration SQL nhúng (database/embed.go) — internal/store import gói này (P2-T03)
COPY database ./database
ARG APP
ARG VERSION=dev
ARG COMMIT=unknown
RUN test -n "${APP}" \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Version=${VERSION} -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Commit=${COMMIT}" \
      -o /out/meshguard "./apps/${APP}"

FROM ${RUNTIME}
COPY --from=build /out/meshguard /usr/local/bin/meshguard
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/meshguard"]
