# Image edge của MeshGuard (P1-T04, §14.4): Caddy 2.11.9 + DNS Cloudflare (ACME DNS-01) + CrowdSec bouncer + rate-limit.
# Base image pin theo digest, module pin theo phiên bản (versions.lock); module Go được kiểm qua checksum DB của Go.
# Chạy non-root (UID 10001). Binary KHÔNG mang file capability (XCADDY_SETCAP=0): Docker đặt
# ip_unprivileged_port_start=0 trong network namespace của container, nên tiến trình non-root bind được 80/443 và
# compose dùng được cap_drop: ALL mà không cần NET_BIND_SERVICE.
ARG CADDY_BUILDER=docker.io/library/caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86
ARG CADDY_RUNTIME=docker.io/library/caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0

FROM ${CADDY_BUILDER} AS build
ENV XCADDY_SETCAP=0 GOTOOLCHAIN=local
RUN mkdir -p /out \
 && xcaddy build v2.11.9 \
      --with github.com/caddy-dns/cloudflare@v0.2.4 \
      --with github.com/hslatman/caddy-crowdsec-bouncer@v0.15.0 \
      --with github.com/mholt/caddy-ratelimit@v0.1.0 \
      --output /out/caddy \
 && /out/caddy list-modules > /out/modules.txt \
 && grep -qx 'dns.providers.cloudflare' /out/modules.txt \
 && grep -qx 'http.handlers.crowdsec' /out/modules.txt \
 && grep -qx 'http.handlers.rate_limit' /out/modules.txt

FROM ${CADDY_RUNTIME}
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/modules.txt /usr/share/caddy/modules.txt
RUN caddy version
USER 10001:10001
