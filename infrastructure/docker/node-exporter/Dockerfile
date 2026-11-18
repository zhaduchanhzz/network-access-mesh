# Image node-exporter (P3-T16; §14.4, §16.1): node_exporter v1.12.1 build lại từ mã nguồn của chính tag đó (module
# github.com/prometheus/node_exporter@v1.12.1 tải qua proxy.golang.org, kiểm bằng checksum DB của Go — cùng commit
# 6044da78 của tag) với Go 1.27.4 ([images.golang]) và các module golang.org/x đã vá (versions.lock
# [sources.node-exporter]). Lý do: image chính thức prom/node-exporter:v1.12.1 (bản mới nhất) build bằng go1.26.5 với
# x/net v0.57.0 — grype báo 3 Critical (GO-2026-6612, GO-2026-6604) và 27 High, chặn bởi gate của workflow `images`.
# Không đổi mã của node_exporter (như cách vá edge — [sources.edge-overrides]).
# Runtime: distroless static-debian13 nonroot ([images.distroless-static]); chạy 65534:65534 (nobody — [ids]
# prometheus_uid); compose đặt pid host, / của host chỉ-đọc, rootfs chỉ-đọc, cap_drop ALL, không publish cổng.
#   docker build -f infrastructure/docker/node-exporter/Dockerfile infrastructure/docker/node-exporter
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GOLANG} AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
ARG NODE_EXPORTER_VERSION=v1.12.1
ARG NODE_EXPORTER_COMMIT=6044da783597cc3b57aef7580ddcdcff58a4ee99
# golang.org/x đã vá: x/net v0.62.0 (GO-2026-6612/6603/6611/6617/6860), x/crypto v0.58.0 (GO-2026-6303/6354/6355),
# x/text v0.43.0 (GO-2026-6629) — đều ≥ 14 ngày tuổi, cùng bản với go.mod của repo khi có.
ARG X_NET=v0.62.0
ARG X_CRYPTO=v0.58.0
ARG X_TEXT=v0.43.0
WORKDIR /work
RUN go mod download -json "github.com/prometheus/node_exporter@${NODE_EXPORTER_VERSION}" > /tmp/module.json \
 && cp -r "$(go env GOMODCACHE)/github.com/prometheus/node_exporter@${NODE_EXPORTER_VERSION}" /src \
 && chmod -R u+w /src
WORKDIR /src
RUN go get "golang.org/x/net@${X_NET}" "golang.org/x/crypto@${X_CRYPTO}" "golang.org/x/text@${X_TEXT}" \
 && go mod verify \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/prometheus/common/version.Version=${NODE_EXPORTER_VERSION#v} -X github.com/prometheus/common/version.Revision=${NODE_EXPORTER_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=meshguard" \
      -o /out/node_exporter . \
 && go version -m /out/node_exporter | grep -E "^/out/node_exporter: go1\.27\.4$" \
 && go version -m /out/node_exporter | grep -E "golang\.org/x/net[[:space:]]+${X_NET}([[:space:]]|$)" \
 && mkdir -p /out/doc && cp LICENSE NOTICE /out/doc/

FROM ${RUNTIME}
COPY --from=build /out/node_exporter /bin/node_exporter
COPY --from=build /out/doc /usr/share/doc/node_exporter
RUN ["/bin/node_exporter", "--version"]
USER 65534:65534
EXPOSE 9100
ENTRYPOINT ["/bin/node_exporter"]
