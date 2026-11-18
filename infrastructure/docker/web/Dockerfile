# Image web của MeshGuard (P4-T01, §12.4, §14.4 hàng "web — tĩnh, do edge phục vụ hoặc container tĩnh, read-only"):
# SPA React (apps/web) build trong Node pin digest ([images.node] của versions.lock) bằng `npm ci` theo package-lock.json
# (--ignore-scripts: không chạy script cài đặt của package nào), rồi phục vụ bằng Caddy 2.11.9 (cùng bản và cùng các
# bản vá golang.org/x/net + klauspost/compress với image edge) chỉ với module chuẩn, trên distroless static nonroot.
# - Một bản build phục vụ cả app.<domain> và admin.<domain>; mọi đường dẫn không phải file tĩnh ⇒ index.html (SPA),
#   /api/* ⇒ 404 (edge định tuyến /api/* tới api, không bao giờ tới đây), dotfile và đường dẫn có "\" ⇒ 404.
# - Header bảo mật (CSP giống hệt portal_headers của edge — test src/security/csp.test.ts) do chính container phát,
#   edge ghi đè cùng giá trị: an toàn cả khi bị phục vụ không qua edge.
# - Không secret, không ghi đĩa: chạy --read-only --cap-drop ALL; XDG_* trỏ vào /tmp (tmpfs khi chạy compose).
# - build tái lập: cùng commit ⇒ cùng dist/ (tên file theo hash nội dung); vite build + scripts/check-dist.mjs (không
#   inline script/style, không tài nguyên ngoài origin, không sourcemap).
#   docker build -f infrastructure/docker/web/Dockerfile .
ARG NODE_IMAGE=docker.io/library/node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
ARG CADDY_BUILDER=docker.io/library/caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86
ARG RUNTIME=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${NODE_IMAGE} AS spa
ENV NODE_ENV=production CI=true npm_config_update_notifier=false
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --include=dev
COPY apps/web/index.html apps/web/vite.config.ts apps/web/tsconfig.json ./
COPY apps/web/public ./public
COPY apps/web/scripts ./scripts
COPY apps/web/src ./src
RUN npm run --silent build && find dist -type f | sort && sha256sum dist/index.html

FROM ${CADDY_BUILDER} AS caddy
ENV XCADDY_SETCAP=0 GOTOOLCHAIN=local CGO_ENABLED=0
RUN mkdir -p /out \
 && xcaddy build v2.11.9 \
      --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
      --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2 \
      --output /out/caddy \
 && /out/caddy version
COPY infrastructure/docker/web/Caddyfile /out/Caddyfile
RUN /out/caddy validate --config /out/Caddyfile --adapter caddyfile

FROM ${RUNTIME}
COPY --from=caddy /out/caddy /usr/bin/caddy
COPY --from=caddy /out/Caddyfile /etc/caddy/Caddyfile
COPY --from=spa /src/apps/web/dist /srv/web
ENV XDG_CONFIG_HOME=/tmp/caddy-config XDG_DATA_HOME=/tmp/caddy-data
RUN ["/usr/bin/caddy", "version"]
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
