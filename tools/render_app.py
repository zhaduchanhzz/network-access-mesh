#!/usr/bin/env python3
"""Render the backend of one environment: compose project mg-app (P2-T16; §4.2, §14.2–§14.4, §16.2 of the master plan)
— api, worker and the one-shot database jobs migrate and db-bootstrap, from the images built from
infrastructure/docker/app, and the static SPA container web (P4-T01a, image infrastructure/docker/web).

Usage:
  python3 tools/render_app.py <env file> <out_dir> [--api-image <ref> --worker-image <ref> --web-image <ref>]

<env file>      infrastructure/environments/<env>/<env>.env — MG_ENV, MG_BASE_DOMAIN and, outside the ci stack, the
                addresses the SSRF-hardened IdP client must refuse on top of its built-in ranges (T-21, P2-T05a):
                MG_LAN_CIDR, MG_TUNNEL_HOST_IPV4, MG_TUNNEL_VPS_IPV4, MG_PUBLIC_IPV4. The process environment
                overrides the file (tools/mgenv.py).
--api-image / --worker-image / --web-image
                images pinned by digest (<name>@sha256:<64 hex>) or local image IDs (sha256:<64 hex>, dev/CI stack),
                always given together. Default: [images.mg-api], [images.mg-worker] and [images.mg-web] of
                versions.lock, which must name the SAME commit (tag) — a worker pinned for another purpose (the key
                ceremony) is never paired with a newer api by accident, and the SPA's generated API client always
                matches the api it calls.

Service `web` (P4-T01a): the SPA (Caddy, static files only) on mg-edge only, alias `web` — the edge (template v9) sends
every path of app./admin. outside /api/* (and the Keycloak console on admin.) to web:8080. No secret, no volume, no
other network; non-root 65532, read-only rootfs, cap_drop ALL, no-new-privileges, RAM/CPU/PID limits; healthcheck by
/usr/bin/healthprobe of the image (distroless). The browser security headers come from the edge alone.

Everything else is a design constant, not an environment value: the edge's static addresses (render_edge.EDGE_IPS,
INTERNAL) give MG_TRUSTED_PROXIES (exactly the edge's address on mg-edge), MG_EDGE_ADMIN_URL and MG_IDP_PLATFORM_ADDR;
the worker's static address on mg-edge is render_edge.APP_IPS (the only source the edge lets reach the IdP's Admin
API); MG_EGRESS_DENY_CIDRS = the Docker address pool of daemon.json, the platform and tenant pools of versions.lock
[ids], plus the environment's LAN, tunnel and public addresses.

Outside the ci stack (no Host Agent there) the worker also gets the Host Agent and the Tenant Orchestrator (P3-T05):
the agent's socket directory /opt/meshguard/run mounted read-only at /run/meshguard, the agent token
(secrets/worker/agent_token, root:mg-sec-worker 0440 — group 20003 the worker already has), MG_AGENT_SOCKET/
MG_AGENT_TOKEN_FILE, and MG_PROVISION_* — the Headscale image of new instances ([images.mg-headscale] digest,
[images.headscale] tag as version), MG_TENANT_NAMESERVERS of the environment, the edge's public listener on mg-edge
(render_edge.EDGE_IPS:443) — plus MG_PROBER_URL when the environment file sets it (the prober of P3-T03a/P3-T16).
MG_PROBER_URL must be exactly the prober's static address on mg-admin (render_monitoring.prober_url()): the prober
serves callers of mg-admin only, and the worker also sits on mg-edge, where the prober's name may resolve — a call by
name can leave from the worker's mg-edge address and be refused (caller_not_allowed, P3-T05c). On the ci stack (no Host
Agent) MG_PROBER_URL alone gives the prober-only configuration of P3-T05c: MG_PROVISION_EDGE_ADDR + MG_PROBER_URL,
relay.probe without the orchestrator.

Outbound e-mail (P3-T05b-mail, tools/render_mail.py): when the environment file sets MG_MAILRELAY_URL (the deployed
Cloudflare Worker), the service `mail-bridge` — the worker image with the subcommand `mailrelay`; SMTP host `mailrelay`,
an alias on `mail` only (a service name is an alias on EVERY network of the service: a client also on mg-egress could
resolve it to the bridge's mg-egress address, where nothing listens — E2E-82) — joins the internal
network `mail` (infrastructure/host/networks.sh; alias mailrelay, SMTP 587 bound to its address there only),
mg-obs (/metrics) and mg-egress (HTTPS to the Worker), with the HMAC key and the TLS key (secrets/mail/, root:mg-sec-mail
0440 — infrastructure/host/mail-secrets.sh); the worker joins `mail` and gets MG_SMTP_ADDR=mailrelay:587, MG_SMTP_TLS=
starttls, MG_SMTP_CA_FILE (the internal CA, public) and MG_SMTP_FROM. Without MG_MAILRELAY_URL nothing of it is rendered.

Writes compose.app.yaml into <out_dir> (on the host: /opt/meshguard/core/compose.app.yaml). tools/test_render_app.py
checks the invariants. Standard library only.
"""
from __future__ import annotations

import ipaddress
import os
import pathlib
import re
import string
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402 — env file of the environment (no secrets)
import render_monitoring  # noqa: E402 — the prober's address on mg-admin (MG_PROBER_URL, P3-T16)
from render_edge import APP_IPS, DOMAIN_RE, EDGE_IPS, INTERNAL  # noqa: E402 — the edge's and the worker's addresses
import render_mail  # noqa: E402 — sender, Worker URL, mail network and files of the outbound relay (P3-T05b-mail)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "4"   # 2: Host Agent + Tenant Orchestrator in the worker (P3-T05); 3: mailrelay (P3-T05b-mail);
#                          4: web — the SPA behind the edge (P4-T01a)
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.app.yaml.tmpl"
VERSIONS = ROOT / "versions.lock"
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")   # name@sha256:… or a local image ID
ENVS = ("ci", "staging", "production")
# Docker's default-address-pools of daemon.json on every host (§14.1, P1-T02): a design constant of the platform.
DOCKER_POOL = "172.24.0.0/13"
# Environment addresses the IdP client must refuse (required outside the ci stack).
EGRESS_ENV = ("MG_LAN_CIDR", "MG_TUNNEL_HOST_IPV4", "MG_TUNNEL_VPS_IPV4", "MG_PUBLIC_IPV4")


class ParamError(ValueError):
    pass


def pools() -> list[str]:
    ids = tomllib.loads(VERSIONS.read_text(encoding="utf-8"))["ids"]
    return [DOCKER_POOL, ids["platform_net_pool"], ids["tenant_net_pool"]]


def egress_deny(env: dict[str, str]) -> str:
    """MG_EGRESS_DENY_CIDRS: the platform's own address space and the environment's addresses (T-21)."""
    out: list[str] = []
    for c in pools():
        out.append(str(ipaddress.ip_network(c)))
    missing = [k for k in EGRESS_ENV if not env.get(k, "").strip()]
    if missing and env.get("MG_ENV") != "ci":
        raise ParamError(f"thiếu {', '.join(missing)} — dải mà HTTP client IdP phải từ chối (T-21)")
    for k in EGRESS_ENV:
        v = env.get(k, "").strip()
        if not v:
            continue
        try:
            out.append(str(ipaddress.ip_network(v, strict=True)) if "/" in v else str(ipaddress.ip_address(v)))
        except ValueError as e:
            raise ParamError(f"{k} không phải địa chỉ/CIDR hợp lệ") from e
    seen: list[str] = []
    for c in out:
        if c not in seen:
            seen.append(c)
    return ",".join(seen)


IMAGE_KEYS = ("mg-api", "mg-worker", "mg-web")


def pinned_images() -> tuple[str, str, str]:
    """(api, worker, web) of versions.lock — the three of ONE commit (tag)."""
    images = tomllib.loads(VERSIONS.read_text(encoding="utf-8")).get("images", {})
    missing = [k for k in IMAGE_KEYS if not images.get(k)]
    if missing:
        raise ParamError(f"versions.lock chưa có {', '.join(f'[images.{k}]' for k in missing)} — api, worker và web phải "
                         "pin từ CÙNG một commit sau khi workflow `images` build commit cần triển khai (P2-T16, P4-T01a), "
                         "hoặc truyền --api-image, --worker-image và --web-image")
    tags = {k: images[k].get("tag") for k in IMAGE_KEYS}
    if len(set(tags.values())) != 1:
        raise ParamError("[images.mg-api], [images.mg-worker] và [images.mg-web] không cùng commit (tag): "
                         + ", ".join(f"{k} {str(v)[:7]}" for k, v in tags.items())
                         + " — pin cả ba từ cùng một lượt workflow `images`")
    api, worker, web = (images[k] for k in IMAGE_KEYS)
    return f"{api['image']}@{api['index']}", f"{worker['image']}@{worker['index']}", f"{web['image']}@{web['index']}"


def headscale_runtime() -> tuple[str, str]:
    """The image of new tenant instances: [images.mg-headscale] (digest) and the Headscale version it patches."""
    images = tomllib.loads(VERSIONS.read_text(encoding="utf-8")).get("images", {})
    hs, upstream = images.get("mg-headscale", {}), images.get("headscale", {})
    digest, version = hs.get("index", ""), upstream.get("tag", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or not re.fullmatch(r"v\d+\.\d+\.\d+", version):
        raise ParamError("versions.lock: [images.mg-headscale].index và [images.headscale].tag là image/phiên bản của "
                         "instance mới (P3-T05)")
    return digest, version


def prober_url(env: dict[str, str]) -> str:
    """MG_PROBER_URL of the environment ("" = none): only the prober's static address on mg-admin is accepted."""
    prober = env.get("MG_PROBER_URL", "").strip()
    if prober and prober.rstrip("/") != render_monitoring.prober_url():
        raise ParamError(f"MG_PROBER_URL phải là {render_monitoring.prober_url()} — địa chỉ tĩnh của prober trên mg-admin; "
                         "gọi bằng tên có thể đi ra từ địa chỉ mg-edge của worker và bị từ chối caller_not_allowed (P3-T05c)")
    return prober.rstrip("/")


def agent_blocks(env: dict[str, str]) -> dict[str, str]:
    """The worker's Host Agent and Tenant Orchestrator (P3-T05) — on the ci stack, which has no agent, only the
    prober-only configuration of P3-T05c when MG_PROBER_URL is set."""
    keys = ("worker_agent_env", "worker_agent_secret", "worker_agent_volume", "agent_secret_def")
    if env.get("MG_ENV") == "ci":
        out = dict.fromkeys(keys, "")
        if prober := prober_url(env):
            out["worker_agent_env"] = "".join("\n      " + x for x in (
                f"MG_PROVISION_EDGE_ADDR: {EDGE_IPS['edge_ip']}:443   # listener công khai của edge (relay.probe)",
                f"MG_PROBER_URL: {prober}   # prober trên mg-admin (P3-T16) — cấu hình chỉ-prober, không orchestrator"))
        return out
    ns = [x.strip() for x in env.get("MG_TENANT_NAMESERVERS", "").split(",") if x.strip()]
    try:
        if not 1 <= len(ns) <= 8 or not all(ipaddress.ip_address(x).is_global for x in ns):
            raise ValueError
    except ValueError as e:
        raise ParamError("MG_TENANT_NAMESERVERS: 1–8 địa chỉ IP công khai (dns.nameservers của instance — RT-07)") from e
    digest, version = headscale_runtime()
    lines = ["MG_AGENT_SOCKET: /run/meshguard/agent.sock          # Host Agent (§11.1) — chỉ worker thấy socket",
             "MG_AGENT_TOKEN_FILE: /run/secrets/agent_token",
             f"MG_PROVISION_HEADSCALE_DIGEST: {digest}",
             f"MG_PROVISION_HEADSCALE_VERSION: {version}",
             f"MG_PROVISION_NAMESERVERS: {','.join(ns)}",
             f"MG_PROVISION_EDGE_ADDR: {EDGE_IPS['edge_ip']}:443   # listener công khai của edge (bước 17/18)"]
    if prober := prober_url(env):
        lines.append(f"MG_PROBER_URL: {prober}   # prober trên mg-admin (project mg-obs, P3-T16)")
    pub = env.get("MG_BACKUP_MANIFEST_PUBKEY", "").strip()
    if pub:  # P3-T11: the worker verifies every backup manifest (§17.1) — the public key of the key ceremony
        if not all(re.fullmatch(r"MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=", k.strip()) for k in pub.split(",")):
            raise ParamError("MG_BACKUP_MANIFEST_PUBKEY phải là khóa công khai Ed25519 (SPKI, base64)")
        lines.append(f"MG_BACKUP_MANIFEST_PUBKEY: {pub}   # kiểm manifest ký của backup tenant (P3-T11)")
    return {
        "worker_agent_env": "".join("\n      " + x for x in lines),
        "worker_agent_secret": "\n      - {source: app_agent_token, target: agent_token}",
        "worker_agent_volume": ("\n      - type: bind"
                                "\n        source: /opt/meshguard/run              # root:mg-sec-worker 0750: agent.sock 0660"
                                "\n        target: /run/meshguard"
                                "\n        read_only: true"
                                "\n        bind:"
                                "\n          create_host_path: false"),
        "agent_secret_def": "\n  app_agent_token: {file: /opt/meshguard/secrets/worker/agent_token}",
    }


MAILRELAY_SERVICE = """\
  # Relay thư ra (P3-T05b-mail — internal/mailrelay, lệnh `meshguard mailrelay` của image worker): SMTP CHỈ trên network
  # `mail` (internal — worker, idp, alertmanager gửi tới mailrelay:587, STARTTLS bắt buộc, CA nội bộ); ra mg-egress tới
  # Worker Cloudflare (HTTPS, chữ ký HMAC); /metrics trên mg-obs (mail-bridge:9090). Không AUTH: chỉ nhận đúng địa chỉ
  # gửi $sender. Tên service KHÁC tên SMTP `mailrelay`: tên service là alias trên MỌI network của service, nên client
  # cũng ở mg-egress (worker, idp, alertmanager) có thể nhận địa chỉ mg-egress của cầu — nơi không có listener SMTP.
  # `mailrelay` chỉ là alias trên network mail ⇒ luôn phân giải ra địa chỉ có listener.
  mail-bridge:
    <<: *hardening
    image: $worker_image
    command: ["mailrelay"]
    user: "65532:65532"
    group_add: ["$mail_gid"]                          # mg-sec-mail (khóa HMAC, khóa TLS) — không nhóm nào khác
    environment:
      MG_ENV: $env
      MG_LOG_LEVEL: info
      MG_INTERNAL_ADDR: ":9090"
      MG_MAILRELAY_SMTP_ADDR: ":$smtp_port"
      MG_MAILRELAY_SMTP_CIDR: $mail_subnet           # nghe SMTP chỉ trên địa chỉ của nó trong network mail
      MG_MAILRELAY_HOSTNAME: $smtp_host
      MG_MAILRELAY_TLS_CERT_FILE: /run/secrets/mail_tls_cert
      MG_MAILRELAY_TLS_KEY_FILE: /run/secrets/mail_tls_key
      MG_MAILRELAY_URL: $relay_url
      MG_MAILRELAY_HMAC_KEY_FILE: /run/secrets/mail_relay_hmac_key
      MG_MAILRELAY_ALLOWED_FROM: $sender
    secrets:
      - {source: app_mail_relay_hmac_key, target: mail_relay_hmac_key}
      - {source: app_mail_tls_key, target: mail_tls_key}
      - {source: app_mail_tls_cert, target: mail_tls_cert}
    networks:
      mail:
        aliases: [$smtp_host]
      mg-obs: {}
      mg-egress:
        gw_priority: 1                            # đường ra duy nhất: HTTPS tới Worker
    mem_limit: 128m
    cpus: 0.5
    pids_limit: 64
    healthcheck:
      test: ["CMD", "/usr/local/bin/meshguard", "healthcheck"]   # /readyz: smtp_listener, hmac_key, tls_certificate
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
      start_interval: 2s
    restart: unless-stopped
    stop_grace_period: 30s

"""


def mail_blocks(env: dict[str, str], worker_image: str) -> dict[str, str]:
    """The relay (P3-T05b-mail) — empty while the environment has no MG_MAILRELAY_URL."""
    keys = ("worker_mail_env", "worker_mail_secret", "worker_mail_network", "mailrelay_service", "mail_secret_def",
            "mail_network_def")
    try:
        url = render_mail.relay_url(env)
        if not url:
            return dict.fromkeys(keys, "")
        _, addr = render_mail.sender(env)
        header = render_mail.from_header(env)
    except render_mail.ParamError as e:
        raise ParamError(str(e)) from e
    host, port = render_mail.SMTP_HOST, render_mail.SMTP_PORT
    service = string.Template(MAILRELAY_SERVICE).substitute(
        worker_image=worker_image, env=env["MG_ENV"], mail_gid=render_mail.mail_gid(), smtp_port=port,
        mail_subnet=render_mail.MAIL_NET["subnet"], smtp_host=host, relay_url=url, sender=addr)
    files = render_mail.FILES
    return {
        "worker_mail_env": (f"\n      MG_SMTP_ADDR: {host}:{port}                 # relay thư ra (P3-T05b-mail): STARTTLS bắt buộc"
                            "\n      MG_SMTP_TLS: starttls"
                            "\n      MG_SMTP_CA_FILE: /run/secrets/mail_ca_cert  # CA nội bộ của mailrelay (công khai)"
                            f'\n      MG_SMTP_FROM: "{header}"'),
        "worker_mail_secret": f"\n      - {{source: {files['ca.crt']}, target: mail_ca_cert}}",
        "worker_mail_network": "\n      mail: {}                                    # → mailrelay:587 (P3-T05b-mail)",
        "mailrelay_service": service,
        "mail_secret_def": "".join(f"\n  {name}: {{file: {render_mail.SECRETS}/{f}}}" for f, name in files.items()),
        "mail_network_def": (f"\n  mail:                                           # internal: worker, idp, alertmanager → mailrelay"
                             f"\n    name: {render_mail.MAIL_NET['name']}\n    external: true"),
    }


def render(env: dict[str, str], api_image: str, worker_image: str, web_image: str) -> dict[str, str]:
    for name, ref in (("api", api_image), ("worker", worker_image), ("web", web_image)):
        if not IMAGE_RE.match(ref):
            raise ParamError(f"image {name} phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
    e = env.get("MG_ENV", "")
    if e not in ENVS:
        raise ParamError(f"MG_ENV phải là một trong {', '.join(ENVS)} (stack dev/CI, staging, production)")
    domain = env.get("MG_BASE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ParamError("MG_BASE_DOMAIN thiếu hoặc không hợp lệ")
    values = {
        "template_version": TEMPLATE_VERSION,
        "api_image": api_image,
        "worker_image": worker_image,
        "web_image": web_image,
        "env": e,
        "base_domain": domain,
        "edge_ip": EDGE_IPS["edge_ip"],
        "edge_admin_url": f"http://{EDGE_IPS['edge_admin_ip']}:{INTERNAL['admin_port']}",
        "idp_platform_addr": f"{EDGE_IPS['edge_ip']}:443",
        "worker_edge_ip": APP_IPS["worker_edge_ip"],
        "egress_deny": egress_deny(env),
        **agent_blocks(env),
        **mail_blocks(env, worker_image),
    }
    return {"compose.app.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values)}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = argv[1:]
    images: dict[str, str] = {}
    flags = ("--api-image", "--worker-image", "--web-image")
    for flag in flags:
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                print(__doc__)
                return 2
            images[flag] = args[i + 1]
            del args[i:i + 2]
    if len(args) != 2 or len(images) not in (0, len(flags)):
        print(__doc__)
        return 2
    try:
        env = mgenv.environment(pathlib.Path(args[0]))
        refs = tuple(images[f] for f in flags) if images else pinned_images()
        files = render(env, *refs)
    except (ParamError, mgenv.EnvError, OSError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(args[1])
    for rel, text in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
