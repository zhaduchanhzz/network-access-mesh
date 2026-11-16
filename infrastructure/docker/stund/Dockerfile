# stund (P1-T04, GW-01, §14.4): STUN responder của Tailscale, build từ tag đã pin (kiểm commit), chạy non-root trên
# distroless. UDP 3478; HTTP debug chỉ nghe 127.0.0.1 (chạy host network).
ARG GOLANG=docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GOLANG} AS build
ARG TS_TAG=v1.104.7
ARG TS_COMMIT=cbc74fe48ef1b1649f69a4d9a602319427e25102
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN git clone --quiet --depth 1 --branch "${TS_TAG}" https://github.com/tailscale/tailscale.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${TS_COMMIT}" \
 && cd /src \
 && go build -trimpath -ldflags="-s -w" -o /out/stund ./cmd/stund

FROM ${RUNTIME}
COPY --from=build /out/stund /usr/local/bin/stund
USER 65532:65532
EXPOSE 3478/udp
ENTRYPOINT ["/usr/local/bin/stund"]
CMD ["-stun=:3478", "-http=127.0.0.1:3479"]
