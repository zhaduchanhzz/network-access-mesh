# infrastructure

Hạ tầng triển khai: `docker/`, `compose/` (`mg-core`, `mg-edge`, `mg-idp`, `mg-backup` — backup có lịch riêng, P2-T03a/P2-T05b), `caddy/`, `crowdsec/`, `headscale/templates/`, `gateway/` (VPS Public Gateway, §14.9), `idp/`, `monitoring/`, `derp/` (Phase 7). Mọi image pin theo digest ghi trong `versions.lock`. Bắt đầu ở Phase 1.
