# Research Evidence — A

> Một phần của [nhật ký bằng chứng nghiên cứu](../research-evidence.md) (P0-T08). Chép nguyên từ kết quả của research agent ngày 2026-11-16; nhận định và trích dẫn giữ nguyên tiếng Anh.

## AREA A - Repository OLife97/headscale-stack-crowdsec @ 1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4 (assessed against Headscale v0.29.7)

**Tóm tắt của agent:** Verdict: use OLife97/headscale-stack-crowdsec as a reference pattern, not as a base to fork. It is a small single-tailnet home-lab stack (9 files, 17 commits, one maintainer, MIT): one Headscale, one third-party custom Caddy image (Cloudflare DNS, GeoIP, CrowdSec bouncer, dynamic DNS) and one CrowdSec engine on a single bridge network, driven by one .env file. All nine files were read in full. Sound and reusable: (1) the Headscale service shape - config mounted read-only, data on a volume, `headscale health` healthcheck, HEADSCALE_* overrides, which v0.29.7 supports natively through viper (environment beats file); (2) the edge pattern - global `crowdsec` app plus per-site handler in Caddy, JSON access log on a shared volume, CrowdSec acquisition `type: caddy`, bouncer key pre-registered through BOUNCER_KEY_<name>; (3) the committed config.yaml contains no key that v0.29.7 rejects. Not production-grade: images are tag-only and two default to `latest`; Headscale is pinned to v0.29.0, seven patch releases behind the 0.29.7 security release. There are no resource limits, capability drops, read-only filesystems, network segmentation, Docker secrets, monitoring or backup tooling; backup is 'stop and copy', upgrade is 'pull and recreate'. The README advertises a Cloudflare DNS-01 challenge that the Caddyfile does not configure. The committed config advertises placeholder DERP addresses (1.2.3.4, 2001:db8::1), keeps Tailscale's public DERP map, and sets no trusted_proxies, node expiry or PKCE. Caddy proxies every path, so /api/v1 and /swagger face the internet, and a country allow-list returns 403 to everyone else including Tailscale nodes. CrowdSec sees only Caddy's HTTP log, enforces only at HTTP level (not STUN), has no Headscale-specific scenarios (none exist in the hub) and shares signals with the Central API by default. Multi-tenant consequences: the stack cannot be replicated per tenant on one host - container names are fixed and host ports 80/443 and 3478/udp are exclusive, while upstream strongly recommends port 443. The workable design is one shared edge (our own pinned Caddy build plus one CrowdSec) routing by hostname to per-tenant Headscale containers on internal networks, with the management API blocked at the edge and reached by the Go backend internally using per-tenant API keys bootstrapped through the CLI. Embedded DERP per tenant works over the shared 443, but each tenant needs its own UDP STUN port because Headscale advertises the port from stun_listen_addr. A shared edge makes CrowdSec bans global across tenants and makes a Caddy reload a platform-wide event (streams are closed on reload by default), so onboarding must avoid disruptive reloads and ban policy needs allow-listing. Hands-on tests still required: config start on v0.29.7, DERP through the proxy, reload behaviour for control and DERP streams, client-IP fidelity through Docker NAT, online SQLite backup and restore, and runtime UIDs. The Caddy image repository was read at an unpinned HEAD, and no image registry was inspected.

## Nhận định

### A-01 · `VERIFIED` · *critical* — 1 Compose architecture

- **Nhận định:** The stack is three services (headscale, caddy, crowdsec) from prebuilt images with no build contexts, all `restart: unless-stopped`, each with a healthcheck; startup order is crowdsec then caddy then headscale. Image tags default to `latest`; only Headscale is tag-pinned (v0.29.0); nothing is pinned by digest.
- **Bằng chứng:** compose.yaml L4 `docker.io/headscale/headscale:${HEADSCALE_VERSION:-latest}`, L32 `ghcr.io/olife97/dhi-caddy-cloudflare:${CADDY_VERSION:-latest}`, L66 `crowdsecurity/crowdsec:${CROWDSEC_VERSION:-latest}`; healthchecks L25-29 `headscale health`, L57-62 `caddy validate`, L83-88 `cscli version`; depends_on L22-24, L54-56; .env.example L6-8. Caddy docs command-line.md L674: validate 'Validates a configuration file, then exits' (a config check, not a liveness probe).
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-02 · `VERIFIED` · *critical* — 1 Compose architecture

- **Nhận định:** Published host ports are Caddy 80 to 8080/tcp, 443 to 8443/tcp and 443 to 8443/udp, plus Headscale 0.0.0.0:3478 to 3478/udp; nothing else is published. Container names (headscale, caddy, crowdsec) and the project name `headstack` are hard-coded.
- **Bằng chứng:** compose.yaml L1 `name: headstack`; L5, L33, L67 `container_name`; L10 `0.0.0.0:3478:3478/udp # STUN/DERP`; L36-38 `80:8080`, `443:8443`, `443:8443/udp # HTTP/3 (QUIC)`; the crowdsec service (L65-88) has no ports key.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-03 · `VERIFIED` — 1 Compose architecture / 9 Persistence

- **Nhận định:** All services share one bridge network `proxy` with no internal-only segment. Headscale state (./headscale/data) and the CrowdSec DB (./crowdsec/data) are bind mounts; Caddy uses named volumes caddy_data, caddy_config, caddy_logs; configs are read-only single-file binds; CrowdSec's /etc/crowdsec is not persisted.
- **Bằng chứng:** compose.yaml L12-13, L40-44, L70-74, L90-96 (`proxy: driver: bridge`; volumes caddy_data, caddy_config, caddy_logs). CrowdSec Docker README L147-150: 'We strongly suggest persisting the Crowdsec configuration and database ... Credentials and configuration: /etc/crowdsec'.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-04 · `VERIFIED` · *critical* — 1 Compose architecture / 11 Gaps

- **Nhận định:** compose.yaml sets no user, cap_drop, security_opt, read_only, tmpfs, resource limits, logging options or secrets on any service. Only Caddy is non-root by image design (uid 65532); CrowdSec's Dockerfile has no USER line and Headscale's image is built on the non-`nonroot` distroless base.
- **Bằng chứng:** compose.yaml full read (96 lines): none of those keys present. dhi-caddy-cloudflare Dockerfile L69 `USER 65532:65532`; crowdsec build/docker/Dockerfile has no USER or HEALTHCHECK line; headscale .goreleaser.yml L106 `base_image: gcr.io/distroless/base-debian13`, no `user:` in the kos block. Upstream container.md L60-62 uses `read_only: true` and `tmpfs: /var/run/headscale`. Runtime UIDs were not inspected.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-05 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** .env.example pins Headscale to v0.29.0 ('tested with'), seven patch releases behind v0.29.7, which upstream labels a security release recommended for all users; if the variable is unset, compose pulls `latest`.
- **Bằng chứng:** .env.example L5-6 'The config.yaml in this stack is tested with HEADSCALE_VERSION=v0.29.0'; headscale CHANGELOG L3-12 '0.29.7 (2026-10-30) ... This is a security release ... We recommend that all users upgrade to Headscale 0.29.7'; releases 0.29.1 to 0.29.7 listed at L3-151.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md

### A-06 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** The committed config.yaml contains no key that v0.29.7 rejects or deprecates. Compared with the v0.29.7 example it omits trusted_proxies, derp.server.verify_clients, the node block, dns.override_local_dns, taildrop, auto_update and oidc, all of which fall back to code defaults.
- **Bằng chứng:** Stack config.yaml L1-70 compared with config.go L575-606 (fatal: acl_policy_path, dns_config.*, dns.use_username_in_magic_dns, oidc.strip_email_domain, oidc.map_legacy_users, randomize_client_port, oidc.expiry; warn: ephemeral_node_inactivity_timeout) and defaults at L454, L460, L490-496; config-example.yaml L47, L107, L155-192, L334, L465-478. Not start-tested (see A-45).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### A-07 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** Headscale natively reads HEADSCALE_* environment variables (viper AutomaticEnv, dots become underscores) with precedence over the config file; space-separated values become lists and empty variables are ignored. The stack uses no templating or envsubst. Structured keys such as dns.extra_records still need the file.
- **Bằng chứng:** config.go L439-442 `envPrefix := headscale`, `viper.SetEnvKeyReplacer(strings.NewReplacer(., _))`, `viper.AutomaticEnv()`; viper v1.21.0 viper.go L1226-1253 ('Env override next' precedes 'Config file next'), L449 empty values rejected; cast v1.10.0 slice.go L94-95 `strings.Fields(v)`; config.go L915-917 and L933 (UnmarshalKey noted as not env-compatible).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### A-08 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** Compose environment overrides bind metrics/debug to 0.0.0.0:9090 and gRPC to 0.0.0.0:50443 inside the container; neither is published or proxied. /metrics is unauthenticated to any container on the shared network. Remote gRPC never starts because Headscale has no TLS and grpc_allow_insecure is false.
- **Bằng chứng:** compose.yaml L17-19; app.go L805 `if tlsConfig != nil || h.cfg.GRPCAllowInsecure {`; getTLSSettings L1102-1107 returns nil without a cert; debug.go L377-378 `debugMux.Handle(/metrics, promhttp.Handler())`; docs/ref/debug.md L65 'Keep the metrics and debug endpoint private to your internal network'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### A-09 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** The Headscale management API in this stack is REST /api/v1 on the main listener, guarded only by a Bearer API key and proxied to the internet by Caddy. The CLI uses an unauthenticated unix socket inside the container; the first API key must be created with that CLI.
- **Bằng chứng:** app.go L600-603 `r.Route(/api ...)` with `r.Use(h.httpAuthenticationMiddleware)` and `/v1/*`; L767 'Start the local gRPC server without TLS and without authentication'; docs/ref/api.md L7-12 'To create an API key, log into your Headscale server and generate one with the default expiration of 90 days: headscale apikeys create'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go

### A-10 · `VERIFIED` — 2 Headscale

- **Nhận định:** Configured values: SQLite at /var/lib/headscale/db.sqlite with WAL; prefixes 100.64.0.0/10 and fd7a:115c:a1e0::/48, sequential; policy.mode database; MagicDNS on with base_domain `ts.net` and Cloudflare public resolvers; text logs at info; unix socket /var/run/headscale/headscale.sock (0770); server_url injected as https://SUBDOMAIN.DOMAIN.
- **Bằng chứng:** Stack config.yaml L1 `server_url: # ENV override with HEADSCALE_SERVER_URL`, L8-11, L29-40, L49-68; compose.yaml L16 `HEADSCALE_SERVER_URL=https://${SUBDOMAIN}.${DOMAIN}`; .env.example L41-43.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/headscale/config/config.yaml

### A-11 · `VERIFIED` · *critical* — 2 Headscale

- **Nhận định:** Headscale refuses to start when dns.base_domain equals the server_url hostname or is a parent suffix of it, so each tenant's MagicDNS domain must sit outside the DNS branch of its control-plane hostname.
- **Bằng chứng:** config.go L39-40 errServerURLSuffix and errServerURLSame; L1253-1258; L1373-1399 `isSafeServerURL`; config-example.yaml L326 'This domain _must_ be different from the server_url domain.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### A-12 · `VERIFIED` · *critical* — 3 Caddy

- **Nhận định:** Caddy is a third-party personal image built with plain `go build` (not xcaddy) on Docker Hardened Image dhi.io/caddy:2, embedding caddy-dns/cloudflare, caddy-maxmind-geolocation, caddy-crowdsec-bouncer (pinned to commit ffdcb7c) and caddy-dynamicdns; the other plugins float at @latest and the image is rebuilt weekly.
- **Bằng chứng:** dhi-caddy-cloudflare Dockerfile L16-21 (imports), L35-40 (`go get ... @latest`, bouncer `@ffdcb7c6f8...`), L64 `FROM dhi.io/caddy:2`, L69; workflow L5 `cron: 0 4 * * 1`, L85-88 tags latest, <version>, <version>-YYYYMMDD, L106-112 provenance attestation. Read at unpinned HEAD on 2026-11-16.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/dhi-caddy-cloudflare/HEAD/Dockerfile

### A-13 · `UNSUPPORTED` · *critical* — 3 Caddy / 10 TLS

- **Nhận định:** The Cloudflare DNS-01 challenge advertised in the README is not configured: the Caddyfile has no tls, acme_dns or dns directive, so certificates come from Caddy's default HTTP-01/TLS-ALPN-01 automation; the Cloudflare token is used only by dynamic_dns.
- **Bằng chứng:** Caddyfile L1-24: global options are only order, http_port, https_port, dynamic_dns, crowdsec; README L13 'Cloudflare DNS challenge'. Caddy docs automatic-https.md L173 'The first two challenge types are enabled by default'; options.md L640 DNS challenge 'when it is enabled (with acme_dns or a tls directive DNS provider)'.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/caddy/Caddyfile

### A-14 · `VERIFIED` · *critical* — 3 Caddy

- **Nhận định:** One site block proxies every path to headscale:8080 for clients whose GeoIP country is in ALLOWED_COUNTRIES; all others, including Tailscale nodes and addresses unknown to the database, get 403. No path is blocked, so /api/v1 (API-key protected) and unauthenticated /swagger are internet-reachable.
- **Bằng chứng:** Caddyfile L27-49 (`handle @geofilter { reverse_proxy headscale:8080 }`, `respond 'Access denied: not allowed' 403`); caddy-maxmind-geolocation main.go L219-229 (unknown mapped to `UNK`, allow-list requires membership), L264 ClientIPVarKey; headscale app.go L588-589, L600-603. README L130 says 'silently dropped'.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/caddy/Caddyfile

### A-15 · `VERIFIED` — 3 Caddy

- **Nhận định:** The Caddyfile relies on reverse_proxy defaults for the Tailscale protocol upgrade (sufficient per upstream) but, unlike upstream's v0.29.7 Caddy example, has no http:// site answering /generate_204, sends no True-Client-IP or X-Real-IP, and Headscale has no trusted_proxies, so Headscale logs the proxy address.
- **Bằng chứng:** reverse-proxy.md L27-32 (POST upgrade, `Upgrade: tailscale-control-protocol`), L148-168 (Caddy example with `handle /generate_204 { respond 204 }` and `header_up True-Client-IP {remote_host}`); config-example.yaml L42-47 'Empty (default) ignores those headers'; Caddyfile L26-49.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/integration/reverse-proxy.md

### A-16 · `REQUIRES_VALIDATION` · *critical* — 3 Caddy / 12 Reuse

- **Nhận định:** Caddy forcibly closes upgraded streaming connections on every config reload unless stream_close_delay is set. A shared edge reloaded for each tenant change could therefore reset all tenants' control and DERP sessions; the effect on Tailscale's non-WebSocket upgrades is untested.
- **Bằng chứng:** Caddy reverse_proxy.md L437 'By default, WebSocket connections are forcibly closed ... when the config is reloaded'; L455 stream_close_delay 'Default: no delay'. Test: reload Caddy with N connected clients and observe ts2021 and DERP reconnects with and without stream_close_delay.
- **Nguồn:** https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/reverse_proxy.md

### A-17 · `VERIFIED` — 3 Caddy / 10 Logging

- **Nhận định:** Caddy writes JSON access logs to /var/log/caddy/access.log on the caddy_logs volume (defaults: roll at 100MiB, keep 10 files or 90 days, mode 600, Authorization and Cookie redacted). Headscale and CrowdSec log to Docker's default json-file driver, which does not rotate. Caddy's admin API stays at localhost:2019.
- **Bằng chứng:** Caddyfile L30-33; Caddy log.md L65, L185, L195, L228, L235; options.md L298 'Default: localhost:2019'; Docker logging/configure.md L28 'By default, no log-rotation is performed'; stack config.yaml L49-51; compose.yaml has no logging key (daemon default assumed unchanged).
- **Nguồn:** https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/log.md

### A-18 · `VERIFIED` — 10 Reachability and firewall

- **Nhận định:** The stack assumes a dynamic-IP site: Caddy's dynamic_dns updates a Cloudflare record every 5 minutes; the README requires a Cloudflare zone and token, a pre-created A/AAAA record, and ports 80, 443 (TCP+UDP) and 3478/UDP open. It omits host firewall rules and upstream's warning that Cloudflare-proxied records do not work.
- **Bằng chứng:** Caddyfile L7-16 (`provider cloudflare {$CF_API_TOKEN}`, `check_interval 5m`, `ip_source simple_http https://icanhazip.com`); README L37-42; reverse-proxy.md L172 'Running Headscale behind a Cloudflare Proxy or Cloudflare Tunnel is not supported and will not work'.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/README.md

### A-19 · `VERIFIED` · *critical* — 4 CrowdSec

- **Nhận định:** CrowdSec installs the crowdsecurity/caddy, base-http-scenarios and linux collections, i.e. generic HTTP scanning, probing and brute-force scenarios. The CrowdSec hub index contains no Headscale- or Tailscale-specific parser, scenario or collection.
- **Bằng chứng:** compose.yaml L76 `COLLECTIONS=crowdsecurity/caddy crowdsecurity/base-http-scenarios crowdsecurity/linux`; hub collections caddy.yaml L2-5, base-http-scenarios.yaml L4-21 (17 scenarios), linux.yaml L2-8; hub .index.json (4.0 MB) grep for headscale|tailscale returned 0 matches while the control match crowdsecurity/caddy-logs succeeded.
- **Nguồn:** https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json

### A-20 · `VERIFIED` · *critical* — 4 CrowdSec

- **Nhận định:** CrowdSec's only log source is Caddy's access log, shared through the caddy_logs volume with label type caddy. It reads no Headscale logs and no host or SSH logs (so the linux collection is inert) and has no visibility of STUN traffic on UDP 3478.
- **Bằng chứng:** crowdsec/acquis.yaml L2-5 `filenames: - /var/log/caddy/*.log`, `labels: type: caddy`; compose.yaml L69-74 (the only log mount is `caddy_logs:/var/log/caddy:ro`); L10 STUN published directly on the headscale service.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/crowdsec/acquis.yaml

### A-21 · `VERIFIED` · *critical* — 4 CrowdSec

- **Nhận định:** Enforcement is the Caddy HTTP handler of caddy-crowdsec-bouncer in streaming mode (decisions pulled every 15s) answering 403 on bans; enable_hard_fails stays false, so Caddy starts without the LAPI. There is no firewall bouncer: banned addresses still complete TLS and reach STUN.
- **Bằng chứng:** Caddyfile L2 `order crowdsec first`, L19-23 (`api_url http://crowdsec:8080`, `ticker_interval 15s`), L28; bouncer crowdsec/caddyfile.go L19-23 (EnableStreaming true, EnableHardFails false); bouncer README L102; internal/httputils/http.go L100-111 `code = http.StatusForbidden`; compose.yaml defines no firewall-bouncer service.
- **Nguồn:** https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/README.md

### A-22 · `VERIFIED` — 4 CrowdSec / 7 Secrets

- **Nhận định:** init.sh generates a 64-hex-character key (`openssl rand -hex 32`) into .env; compose passes it to CrowdSec as BOUNCER_KEY_CADDY, whose entrypoint runs `cscli bouncers add` when that name is not registered, and to Caddy as api_key. Rotating the key requires deleting the bouncer first.
- **Bằng chứng:** init.sh L132-133; compose.yaml L50 and L77 `BOUNCER_KEY_CADDY=${CROWDSEC_BOUNCER_KEY}`; docker_start.sh L138-146, L470-477; CrowdSec Docker README L247 'You cannot use this process to update an existing bouncer without first deleting it.'
- **Nguồn:** https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/build/docker/docker_start.sh

### A-23 · `VERIFIED` — 4 CrowdSec

- **Nhận định:** CrowdSec registers with the Central API by default (signal sharing) because DISABLE_ONLINE_API is unset; console enrollment is off (no ENROLL_KEY). The entrypoint upgrades hub content on every start, and credentials live in the unpersisted /etc/crowdsec.
- **Bằng chứng:** docker_start.sh L91-99 and L219 (`cscli hub upgrade` when the data dir is a volume), L413-423 (`cscli capi register`), L425-438; CrowdSec Docker README L282 'DISABLE_ONLINE_API | false | Disable online API registration for signal sharing'; compose.yaml L69-80.
- **Nguồn:** https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/build/docker/docker_start.sh

### A-24 · `VERIFIED` — 4 CrowdSec

- **Nhận định:** AppSec/WAF is not enabled (no appsec_url, no `appsec` directive, no APPSEC_* variables) although the module is compiled into the image. The only custom CrowdSec policy is an init.sh-generated profile: 4h ban for IP-scope alerts plus an http_default webhook notification (NTFY or Gotify).
- **Bằng chứng:** Caddyfile L19-23, L28; compose.yaml L75-80; bouncer imports.go L7-10 (appsec, crowdsec, http, layer4); bouncer README L103 `appsec_url ... <empty> (disabled)`; init.sh L46-96 (`duration: 4h`, `notifications: - http_default`). CROWDSEC_NOTIFY_AUTH_HEADER is passed to the container but never referenced in the generated http.yaml.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/init.sh

### A-25 · `VERIFIED` · *critical* — 4 CrowdSec / 12 Reuse

- **Nhận định:** The bouncer keeps one decision store per Caddy instance, shared by all handlers and keyed by client IP, so on a shared edge a ban triggered on one tenant hostname blocks that address for every tenant and for the portal.
- **Bằng chứng:** bouncer README L28-29 'Multiple independent HTTP Handlers and Connection Matchers can share the storage exposed by the App'; http/http.go L96-99 `ctx, ip = httputils.EnsureIP(ctx)` then `h.crowdsec.IsAllowed(ctx, ip)`; Caddyfile L19-23 single global crowdsec app.
- **Nguồn:** https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/http/http.go

### A-26 · `VERIFIED` — 5 OIDC

- **Nhận định:** OIDC is configured purely by environment: HEADSCALE_OIDC_ISSUER (default https://accounts.google.com), _CLIENT_ID, _CLIENT_SECRET, _ONLY_START_IF_OIDC_IS_AVAILABLE=true and an allow-list (_ALLOWED_USERS active; _ALLOWED_DOMAINS and _ALLOWED_GROUPS commented). Google is the documented IdP. Upstream ANDs multiple filters; the stack says choose one.
- **Bằng chứng:** .env.example L45-65; README L103-113 (Google OAuth2 steps, redirect URI ending /oidc/callback), L154-164; headscale docs/ref/oidc.md L72-74 'In case multiple filters are configured, a user needs to pass all of them.'
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/.env.example

### A-27 · `VERIFIED` — 5 OIDC

- **Nhận định:** PKCE is not enabled (Headscale default false; upstream marks it recommended), no scope override is offered for the groups filter, and the client secret is a plain environment variable rather than client_secret_path. OIDC is active by default with placeholder credentials; an empty issuer disables it.
- **Bằng chứng:** config.go L485 `viper.SetDefault(oidc.pkce.enabled, false)`; oidc.md L47-51 'PKCE is recommended', L123 scope including groups; .env.example L47-49; config-example.yaml L394-399 (client_secret_path); app.go L195 `if cfg.OIDC.Issuer != ...`; viper.go L449 (empty env ignored).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/oidc.md

### A-28 · `VERIFIED` · *critical* — 5 OIDC

- **Nhận định:** In v0.29.7 `oidc.expiry` is removed and fatal if set; node key lifetime comes from node.expiry (default 0, never expires) or oidc.use_expiry_from_token. The stack sets neither, so OIDC-registered nodes never expire by default.
- **Bằng chứng:** config.go L605-606 `depr.fatalIfSet(oidc.expiry, node.expiry)`, L493 `viper.SetDefault(node.expiry, 0)`; CHANGELOG L450 'oidc.expiry has been removed; use node.expiry instead'; oidc.md L147-155. The config-example comment at L159 still mentions oidc.expiry and is stale.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### A-29 · `VERIFIED` · *critical* — 6 Embedded DERP/STUN

- **Nhận định:** Embedded DERP is enabled with region 999 and code `headscale`, STUN on 0.0.0.0:3478 (published UDP) and key at /var/lib/headscale/derp_server_private.key; verify_clients is absent and defaults to true; Tailscale's public DERP map stays in derp.urls, refreshed every 24h.
- **Bằng chứng:** Stack config.yaml L12-27; config.go L460 `viper.SetDefault(derp.server.verify_clients, true)`; docs/ref/derp.md L139 'Client verification is enabled by default.'; derp_server.go L60-63 (verify URL set, fail-open false).
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/headscale/config/config.yaml

### A-30 · `VERIFIED` · *critical* — 6 Embedded DERP/STUN

- **Nhận định:** The committed config sets derp.server.ipv4 1.2.3.4 and ipv6 2001:db8::1 with DERP enabled. Headscale copies both into the advertised DERP node, and Tailscale clients use a set address 'instead of using DNS'. Neither .env.example nor the README tells users to change them.
- **Bằng chứng:** Stack config.yaml L21-22; derp_server.go L126-127 `IPv4: d.cfg.IPv4, IPv6: d.cfg.IPv6`; tailscale v1.104.7 tailcfg/derpmap.go L216-221 'IPv4 optionally forces an IPv4 address to use, instead of using DNS.' The client-side effect was not tested (see A-45).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/derp/server/derp_server.go

### A-31 · `VERIFIED` · *critical* — 6 Embedded DERP/STUN

- **Nhận định:** Headscale derives the embedded DERP node's hostname and TLS port from server_url and its STUN port from the port in stun_listen_addr; STUN is served directly over UDP and cannot go through the HTTP proxy.
- **Bằng chứng:** derp_server.go L74-100 (host and port from `url.Parse(d.serverURL)`, 443 for https), L132-142 `localDERPregion.Nodes[0].STUNPort = portSTUN`; reverse-proxy.md L21-23 and L71 'STUN ... requires udp/3478 to be served publicly.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/derp/server/derp_server.go

### A-32 · `VERIFIED` — 6 Embedded DERP/STUN

- **Nhận định:** Upstream states the embedded DERP has 'no speed or throughput optimisations' and cannot serve captive-portal checks (/generate_204 on tcp/80); it is added alongside Tailscale Inc.'s DERP servers unless `derp.urls: []` is set, which then makes it a single point of failure.
- **Bằng chứng:** docs/ref/derp.md L33-35, L43, L46-49 'Single point of failure', L170-172 'There are no speed or throughput optimisations, the main purpose is to assist in node connectivity.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/derp.md

### A-33 · `VERIFIED` · *critical* — 7 Secrets

- **Nhận định:** All secrets (Cloudflare token, bouncer key, webhook token, OIDC client secret) sit in a plaintext .env that init.sh creates without setting permissions and reach containers as environment variables; `env_file` hands every one of them to Headscale. Docker secrets are unused; no real secret is committed.
- **Bằng chứng:** .env.example L14-15, L36-38, L49 (placeholders only); init.sh L129-135 (`cp .env.example .env`; no chmod anywhere in the script); compose.yaml L14 `env_file: .env`, L45-51, L75-80, no `secrets:` key; .gitignore L1. File-based alternatives exist: config-example.yaml L396-399, docker_start.sh L506-514. Headscale's own key files are written 0600 (app.go L91).
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-34 · `VERIFIED` — 8 Startup initialisation

- **Nhận định:** init.sh creates bind-mount directories, writes CrowdSec profiles.yaml and notifications/http.yaml, downloads GeoLite2-Country.mmdb and creates .env with a random bouncer key, each guarded by a file-existence check. It is mandatory: three bind-mount sources in compose.yaml exist only after it runs. It needs no root.
- **Bằng chứng:** init.sh L9-11, L35-43, L46-96, L101-124, L129-135; compose.yaml L44, L73-74 reference files absent from the 9-file repository; Docker bind-mounts.md L88-89 'Docker automatically creates the directory ... It's always created as a directory.' Tools used: bash, wget, sed, stat -c, openssl.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/init.sh

### A-35 · `VERIFIED` — 8 Startup initialisation

- **Nhận định:** init.sh's Headscale-config download is dead code on a fresh clone because config.yaml is committed (despite being in .gitignore) and would fetch the unpinned `main` branch. Other risks: GeoIP database fetched without checksum from a third-party GitHub mirror, an interactive `read` prompt, relative paths, `set -e` only.
- **Bằng chứng:** init.sh L4, L15-26 (wget of juanfont/headscale/main/config-example.yaml; sed on `db_path:` and two removed keys, none present in the v0.29.7 example), L102 `https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb`, L109 `read -p`; .gitignore L7; README L72 claims the config is downloaded.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/init.sh

### A-36 · `UNSUPPORTED` · *critical* — 9 Persistence and backup

- **Nhận định:** The stack ships no backup mechanism: only README advice to stop the stack and copy db.sqlite, *.key and .env. There is no script, schedule, retention, off-site copy, restore procedure or online SQLite method, and the list omits caddy_data, crowdsec/data and generated configs.
- **Bằng chứng:** README L231-249 (table of three paths; 'Always stop the stack before running your backup script: docker compose down'), L251-257; compose.yaml L41-43 and L70 (volumes absent from the README table); no backup file in the 9-file inventory.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/README.md

### A-37 · `VERIFIED` · *critical* — 9 Persistence and backup

- **Nhận định:** The README's update procedure is `docker compose pull` followed by `up -d --force-recreate`, with no backup step or version guidance. Upstream requires stop, backup, then upgrade, one minor version at a time, and since 0.29.0 blocks skipped minors and downgrades.
- **Bằng chứng:** README L209-220; headscale docs/setup/upgrade.md L3-17 ('Its required to update from one stable version to the next ... without skipping minor versions'; 'Create a backup of your installation'); CHANGELOG L359-364 'Headscale now enforces a strict version upgrade path'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/upgrade.md

### A-38 · `REQUIRES_VALIDATION` · *critical* — 9 Persistence and backup

- **Nhận định:** A consistent hot backup of a running tenant's SQLite database is not described by the stack or by upstream, which only document stopping Headscale and copying files; the distroless Headscale image has no shell or sqlite3, so an online method needs a sidecar and must be proven.
- **Bằng chứng:** headscale container.md L100 'based on a distroless image that does not contain a shell or any other debug tools'; upgrade.md L13-14, L32-36; stack config.yaml L39 `write_ahead_log: true`. Test: sqlite3 `.backup` or `VACUUM INTO` from a sidecar under registration load, then restore db plus key files into a fresh instance.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/install/container.md

### A-39 · `UNSUPPORTED` — 11 Production-ready claim

- **Nhận định:** The 'production-ready' self-description is not borne out: no digest pinning, resource limits, container hardening, network segmentation, Docker secrets, monitoring, automated backup or restore procedure. The repository has 17 commits by one maintainer, no issues, and its README says parts are 'Vibe-coded'.
- **Bằng chứng:** README L3 'A production-ready, minimal, and fully environment-driven Docker Compose stack', L290; compose.yaml full read; the GitHub commits page lists 17 commits (newest 1afd96c, 2026-06-18) and the issues page shows 0 results (both read via WebFetch); LICENSE L1-3 MIT.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/README.md

### A-40 · `UNSUPPORTED` · *critical* — 12 Reuse verdict

- **Nhận định:** Headscale does not provide multiple tailnets in one instance: upstream's package description says it implements 'a narrow scope, a single Tailscale network (tailnet)'. Tenant isolation therefore has to come from one instance per tenant, as planned.
- **Bằng chứng:** headscale .goreleaser.yml L63-68 'It implements a narrow scope, a single Tailscale network (tailnet), suitable for a personal use, or a small open-source organisation.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/.goreleaser.yml

### A-41 · `VERIFIED` · *critical* — 12 Reuse verdict / 10 Ports

- **Nhận định:** Upstream strongly recommends serving Headscale over HTTPS on port 443 because the Tailscale client 'assumes HTTPS on port 443 in certain situations'; it lists udp/3478 as public when embedded DERP is enabled, tcp/9090 as never public, and tcp/50443 as needed only for remote gRPC.
- **Bằng chứng:** headscale docs/setup/requirements.md L17-34 (ports in use), L49-51 footnote 'sticking with HTTPS on port 443 is strongly recommended for production setups'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/requirements.md

### A-42 · `ASSUMED` · *critical* — 12 Reuse verdict

- **Nhận định:** Reuse verdict (a): the headscale service shape (read-only config, data volume, `headscale health`, HEADSCALE_* overrides) and config skeleton are a usable per-tenant starting point; version pin, fixed names and ports, placeholder DERP addresses, shared env_file and missing trusted_proxies, node.expiry, PKCE and hardening must all change.
- **Bằng chứng:** Synthesis of A-01, A-02, A-04, A-05, A-06, A-07, A-15, A-28, A-30 and A-33; no source states this verdict.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-43 · `ASSUMED` · *critical* — 12 Reuse verdict

- **Nhận định:** Reuse verdict (b): the edge pattern (global crowdsec app, per-site `crowdsec` handler, JSON access log on a volume, acquisition type caddy, BOUNCER_KEY_<name>) transfers to one shared Caddy plus one CrowdSec; the single-site Caddyfile, dynamic_dns, GeoIP allow-list, floating third-party image and unpersisted CrowdSec config do not.
- **Bằng chứng:** Synthesis of A-03, A-12, A-14, A-18, A-20, A-21 and A-22; no source states this verdict.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/caddy/Caddyfile

### A-44 · `ASSUMED` · *critical* — 12 Reuse verdict

- **Nhận định:** On one host, replicating the whole stack per tenant is blocked by exclusive host ports 80/443 and multiplies CrowdSec engines, while isolating bans and certificates per tenant; a shared edge centralises TLS and bans but is a single blast radius and still needs one UDP STUN port per tenant.
- **Bằng chứng:** Inference from A-02 (fixed host ports), A-25 (shared decision store), A-31 (STUN port per instance), A-41 (port 443 recommendation) and A-16 (reload impact); not tested.
- **Nguồn:** https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml

### A-45 · `REQUIRES_VALIDATION` — 2 Headscale / 6 DERP / 4 CrowdSec

- **Nhận định:** Not established by reading: whether the committed config starts cleanly on v0.29.7 (source reading suggests yes), whether clients can use the embedded DERP through Caddy with the placeholder addresses, and whether Caddy sees true client IPs for IPv4 and IPv6 through Docker's published ports.
- **Bằng chứng:** Tests: (1) `headscale configtest` then `serve` on v0.29.7 with the compose environment; (2) `tailscale debug derp headscale` and `tailscale netcheck`; (3) compare `request.remote_ip` in access.log for external IPv4 and IPv6 clients. Basis for (1): viper.go L1250-1272 (nil config values fall through to defaults) and config.go L643-646.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

## Hệ quả thiết kế (agent đề xuất)

- Do not fork this repository. Borrow two patterns only: the Headscale service shape for a per-tenant template, and the Caddy plus CrowdSec wiring for a shared edge. Everything else must be written for multi-tenancy.
- On a single-IP host one shared TLS edge on 443 is effectively mandatory (exclusive host ports; upstream strongly recommends 443). Per-tenant Headscale containers should publish no TCP ports and be reached by the edge over Docker networks by service name.
- Embedded DERP per tenant needs a unique UDP STUN port per tenant, set identically in stun_listen_addr and the port mapping, because Headscale advertises the port from stun_listen_addr. Track the allocation in PostgreSQL and open the range in the host firewall, or move early to a shared STUN/DERP to avoid port sprawl.
- Never render derp.server.ipv4/ipv6 placeholders: emit the host's real public addresses or omit the keys. Decide per tenant whether to set `derp.urls: []` (no relaying through Tailscale Inc., but a single point of failure) or keep the public map as fallback.
- Block /api/* and /swagger* at the public edge. The Go backend should call http://<tenant-headscale>:8080/api/v1 on an internal network with a per-tenant API key created at provisioning time through the CLI over the unix socket (docker exec), stored encrypted, and rotated before the default 90-day expiry.
- Make a rendered config.yaml per tenant the source of truth and keep environment overrides to a few scalars; structured settings (extra DNS records, split DNS, OIDC extra params) cannot come from environment. Validate every render with `headscale configtest` on the exact pinned image.
- Set trusted_proxies to the edge network CIDR and send True-Client-IP and X-Real-IP from Caddy so Headscale logs real client addresses; add an http:// handler answering /generate_204 as in upstream's Caddy example.
- Give each tenant a unique dns.base_domain outside the DNS branch of its server_url hostname (Headscale refuses a base domain that is a parent suffix), and never use `ts.net`.
- For OIDC: enable PKCE, set node.expiry explicitly (the default is never), deliver the client secret through client_secret_path from a secret file, and never emit `oidc.expiry` (fatal in v0.29.7).
- Pin Headscale v0.29.7 by digest and harden every container: read_only plus tmpfs /var/run/headscale, explicit user, cap_drop ALL, no-new-privileges, memory/CPU/pids limits, log rotation, and separate networks for edge-to-tenant, backend-to-tenant and monitoring. Do not pass a shared .env through env_file.
- Build our own Caddy image with pinned module versions (CrowdSec bouncer, optionally a DNS provider for DNS-01) instead of depending on a personal GHCR image whose plugins float at @latest. The referenced Dockerfile (go build, replace directives, non-root uid) is a usable reference.
- Tenant onboarding must not cause disruptive full Caddy reloads: test stream_close_delay, or serve tenants from a static wildcard or on-demand-TLS site whose upstream is resolved dynamically. Wildcard certificates require DNS-01 and therefore a DNS provider module.
- With one shared CrowdSec, a ban applies to every tenant and the portal. Plan allow-lists (backend, monitoring, known tenant egress), an unban path in the portal, per-tenant access-log files for attribution, a decision on Central API sharing, a persisted /etc/crowdsec and pinned hub content. Enforcement is HTTP-only; STUN and TLS-level blocking need a host firewall bouncer.
- Do not enable country allow-listing by default on a VPN control plane: it returns 403 to roaming nodes and to addresses unknown to the GeoIP database. If offered, make it a per-tenant option.
- Implement backups in the platform: per-tenant online SQLite backup from a sidecar (the Headscale image has no shell), plus noise and DERP key files and the rendered config; snapshot before every upgrade and follow upstream's one-minor-at-a-time rule, since downgrades are blocked.
- Scrape each tenant's :9090/metrics from a monitoring network only; the endpoint is unauthenticated and must never be published or proxied.
- Inference to confirm in the DERP research area: a later shared derper verifies clients against a single Headscale /verify URL, so multi-tenant verification would need a fan-out service or per-tenant relays.

## Câu hỏi mở

- Does a config derived from this stack start cleanly on Headscale v0.29.7? Run `headscale configtest` and `serve` with the intended environment on the pinned image.
- Does embedded DERP work through the Caddy proxy, and what do clients do when the DERP map carries a wrong forced IPv4/IPv6? Check with `tailscale debug derp headscale` and `tailscale netcheck`.
- On a Caddy reload, are ts2021 control connections and DERP connections closed, how large is the reconnect storm with N clients, and does stream_close_delay mitigate it?
- Does Caddy see real client addresses for both IPv4 and IPv6 through Docker's published ports on the target Ubuntu host? This decides whether CrowdSec decisions and Headscale trusted_proxies are meaningful.
- Which UID do headscale/headscale:v0.29.7 and crowdsecurity/crowdsec actually run as, and can Headscale run with a non-root `user:` plus `read_only: true` given volume ownership?
- Is an online SQLite backup (sqlite3 `.backup` or `VACUUM INTO` from a sidecar) consistent under load, and does a restore of database plus key files into a fresh instance keep all nodes enrolled?
- Do all official clients, including iOS and Android, honour a non-3478 STUN port advertised in the DERP map, so that per-tenant STUN ports are viable?
- Do normal tailscaled request patterns (many nodes behind one NAT, bursts of 401/403 on key expiry) trigger the base-http CrowdSec scenarios and cause cross-tenant bans?
- Which certificate strategy fits N tenant hostnames: per-host HTTP-01, a wildcard via DNS-01, or on-demand TLS with an authorisation endpoint, and what are the ACME rate-limit implications?
- Is participation in the CrowdSec Central API (signal sharing, community blocklist) acceptable for tenant traffic, and is a platform-wide ban scope acceptable?
- Exactly which Headscale paths must stay public for clients (/ts2021, /key, /derp*, /register, /auth, /oidc/callback, /machine/*, /bootstrap-dns, /apple, /windows, /health) and which can be blocked at the edge (/api, /swagger, /verify, /version)?
- How will per-tenant API keys be rotated before their default 90-day expiry without operator action?
- Does CrowdSec log an error for every alert when the generated profile references the http_default notification but no webhook URL is set?

## Nguồn đã đọc

- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/compose.yaml (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/.env.example (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/.gitignore (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/LICENSE (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/README.md (full, 293 lines)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/caddy/Caddyfile (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/crowdsec/acquis.yaml (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/headscale/config/config.yaml (full)
- https://raw.githubusercontent.com/OLife97/headscale-stack-crowdsec/1afd96c5977a0ef4ac1013a21ec2bfc5360a33e4/init.sh (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/config-example.yaml (full, 497 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/integration/reverse-proxy.md (full, 272 lines)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go (L410-445, L506-720, L720-1060, L1095-1545)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/app.go (grep plus L440-620, L700-905, L1040-1180)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/derp/server/derp_server.go (L1-420)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/derp/derp.go (grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/debug.go (grep plus L15-60, L360-390)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/handlers.go (grep plus VerifyHandler section)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/util/file.go (grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/health.go (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/cmd/headscale/cli/configtest.go (grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md (L1-470 plus heading grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/.goreleaser.yml (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/go.mod (grep)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/install/container.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/upgrade.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/requirements.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/derp.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/oidc.md (L1-330)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/api.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/debug.md (L60-120)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/tls.md (L1-30)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.0/config-example.yaml (grep of key lines)
- https://raw.githubusercontent.com/tailscale/tailscale/v1.104.7/tailcfg/derpmap.go (grep, DERPNode fields)
- https://raw.githubusercontent.com/spf13/viper/v1.21.0/viper.go (L414-456, L1149-1175, L1222-1290, L1388-1404)
- https://raw.githubusercontent.com/spf13/cast/v1.10.0/slice.go (L60-110)
- https://raw.githubusercontent.com/OLife97/dhi-caddy-cloudflare/HEAD/Dockerfile (full, unpinned HEAD)
- https://raw.githubusercontent.com/OLife97/dhi-caddy-cloudflare/HEAD/README.md (full, unpinned HEAD)
- https://raw.githubusercontent.com/OLife97/dhi-caddy-cloudflare/HEAD/compose.yaml and example.env (full, unpinned HEAD)
- https://raw.githubusercontent.com/OLife97/dhi-caddy-cloudflare/HEAD/.github/workflows/docker-image.yml (full, unpinned HEAD)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/README.md (full)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/imports.go (full)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/crowdsec/caddyfile.go (L1-110)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/crowdsec/crowdsec.go (grep)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/http/http.go (L84-134)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/internal/httputils/context.go and http.go (L1-120)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/go.mod (L1-60)
- https://raw.githubusercontent.com/porech/caddy-maxmind-geolocation/master/README.md (L1-160)
- https://raw.githubusercontent.com/porech/caddy-maxmind-geolocation/master/main.go (grep)
- https://raw.githubusercontent.com/mholt/caddy-dynamicdns/master/README.md (L1-200)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/build/docker/docker_start.sh (full, 576 lines)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/build/docker/README.md (grep plus L60-70, L84-92, L124-205, L240-300, L326-334)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/build/docker/Dockerfile and Dockerfile.debian (grep for FROM, USER, HEALTHCHECK, ENTRYPOINT)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/pkg/csplugin/broker.go (grep)
- https://raw.githubusercontent.com/crowdsecurity/hub/master/collections/crowdsecurity/caddy.yaml, base-http-scenarios.yaml, linux.yaml (full)
- https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json (grep only, 4.0 MB)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/log.md (grep plus L152-196)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/options.md (grep plus L606-640)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/automatic-https.md (grep)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/directives/reverse_proxy.md (grep)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/command-line.md (L667-690)
- https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/concepts.md (grep)
- https://raw.githubusercontent.com/docker/docs/main/content/manuals/engine/storage/bind-mounts.md (grep)
- https://raw.githubusercontent.com/docker/docs/main/content/manuals/engine/logging/configure.md (grep)
- https://raw.githubusercontent.com/docker/docs/main/content/reference/compose-file/services.md (L628-650)
- https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/README.md (grep)
- https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/master/README.md (full; no database file downloaded)
- https://github.com/OLife97/headscale-stack-crowdsec/commits/main/ (WebFetch, commit list)
- https://github.com/OLife97/headscale-stack-crowdsec/issues?q=is%3Aissue (WebFetch, 0 results)
- https://github.com/OLife97/dhi-caddy-cloudflare (WebFetch, root listing)
- https://github.com/hslatman/caddy-crowdsec-bouncer/tree/ffdcb7c6f8619effc7510bc0db0edec3609a1d28 and /internal/httputils (WebFetch, directory listings)
- https://github.com/porech/caddy-maxmind-geolocation (WebFetch, root listing)

**Nguồn không đọc được:**

- No required source failed. The following were wrong path guesses (HTTP 404), each resolved by reading the correct file listed in sources_read:
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/docker/docker_start.sh and docker/README.md (correct location: build/docker/)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/Dockerfile (correct location: build/docker/Dockerfile)
- https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/pkg/csplugin/pluginconfig.go and pkg/csplugin/config.go (broker.go read instead)
- https://raw.githubusercontent.com/porech/caddy-maxmind-geolocation/master/maxmind_geolocation.go (main.go read instead)
- https://raw.githubusercontent.com/hslatman/caddy-crowdsec-bouncer/ffdcb7c6f8619effc7510bc0db0edec3609a1d28/crowdsec.go, main.go, http/caddyfile.go and internal/httputils/{httputils,ip,utils,response,writer}.go (imports.go, context.go and http.go read instead)
- Not attempted by rule or scope: api.github.com; container registries (image digests, labels and actual runtime user of headscale/headscale, crowdsecurity/crowdsec and ghcr.io/olife97/dhi-caddy-cloudflare were not inspected); the OLife97/dhi-caddy-cloudflare repository could only be read at an unpinned HEAD.
