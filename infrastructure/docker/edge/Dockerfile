# Image edge của MeshGuard (P1-T04, §14.4): Caddy 2.11.9 + DNS Cloudflare (ACME DNS-01) + CrowdSec bouncer + rate-limit.
# Base image pin theo digest, module pin theo phiên bản (versions.lock); module Go được kiểm qua checksum DB của Go.
# Runtime là distroless static (Caddy là binary Go tĩnh): không shell, không trình quản lý gói, không thư viện C —
# bản đầu dùng caddy:2.11.9-alpine bị grype chặn vì CVE-2026-4738 (zlib, Critical) ở lớp Alpine.
# Nâng golang.org/x/net và klauspost/compress để vá GO-2026-6860 và GO-2026-6865 (High).
# Chạy non-root (UID 10001). Binary KHÔNG mang file capability (XCADDY_SETCAP=0): Docker đặt
# ip_unprivileged_port_start=0 trong network namespace của container, nên tiến trình non-root bind được 80/443 và
# compose dùng được cap_drop: ALL mà không cần NET_BIND_SERVICE.
ARG CADDY_BUILDER=docker.io/library/caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${CADDY_BUILDER} AS build
ENV XCADDY_SETCAP=0 GOTOOLCHAIN=local CGO_ENABLED=0
RUN mkdir -p /out /rootfs/config/caddy /rootfs/data/caddy /rootfs/etc/caddy \
 && xcaddy build v2.11.9 \
      --with github.com/caddy-dns/cloudflare@v0.2.4 \
      --with github.com/hslatman/caddy-crowdsec-bouncer@v0.15.0 \
      --with github.com/mholt/caddy-ratelimit@v0.1.0 \
      --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
      --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2 \
      --output /out/caddy \
 && /out/caddy list-modules > /out/modules.txt \
 && grep -qx 'dns.providers.cloudflare' /out/modules.txt \
 && grep -qx 'http.handlers.crowdsec' /out/modules.txt \
 && grep -qx 'http.handlers.rate_limit' /out/modules.txt

FROM ${RUNTIME}
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/modules.txt /usr/share/caddy/modules.txt
COPY --from=build --chown=10001:10001 /rootfs/config /config
COPY --from=build --chown=10001:10001 /rootfs/data /data
COPY --from=build /rootfs/etc/caddy /etc/caddy
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
RUN ["/usr/bin/caddy", "version"]
USER 10001:10001
EXPOSE 80 443
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
