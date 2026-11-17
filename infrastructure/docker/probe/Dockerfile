# Image prober (P3-T03a; §14.4, §16.1, §11.3 bước 17–18): meshguard-probe (apps/probe) — STUN binding, HTTPS GET với
# SNI/Host chỉ định, kiểm tra edge (bước 18) và relay (bước 17), RPC nội bộ cho worker. Go tĩnh, thư viện chuẩn +
# internal/kit (module ngoài: prometheus/client_golang và google/uuid — tải qua proxy, kiểm bằng go.sum, -mod=readonly);
# không thêm module Go nào. Không giữ secret. blackbox_exporter của §14.4 được thêm cùng bộ monitoring (P3-T16).
# Runtime: distroless static-debian13 nonroot (versions.lock [images.distroless-static], cùng digest với api/worker) —
# có sẵn kho CA hệ thống (/etc/ssl/certs) cho chứng chỉ ACME công khai của edge; không shell, không trình quản lý gói.
# Chạy 65532:65532; compose đặt rootfs chỉ-đọc, cap_drop ALL, no-new-privileges, không publish cổng.
#   docker build -f infrastructure/docker/probe/Dockerfile --build-arg VERSION=… --build-arg COMMIT=… .
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GOLANG} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
COPY apps/probe ./apps/probe
COPY internal/kit ./internal/kit
ARG APP=probe
ARG VERSION=dev
ARG COMMIT=unknown
RUN test "${APP}" = probe \
 && go build -trimpath \
      -ldflags="-s -w -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Version=${VERSION} -X github.com/zhaduchanhzz/network-access-mesh/internal/kit/buildinfo.Commit=${COMMIT}" \
      -o /out/meshguard-probe ./apps/probe

FROM ${RUNTIME}
COPY --from=build /out/meshguard-probe /usr/local/bin/meshguard-probe
RUN ["/usr/local/bin/meshguard-probe", "version"]
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/meshguard-probe"]
CMD ["serve"]
