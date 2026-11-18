#!/usr/bin/env python3
"""Render the edge (Caddy) of one host: Caddyfile + compose project mg-edge (P1-T06, §14.4, §14.6 of the master plan).

Usage:  python tools/render_edge.py <params.json> <out_dir>

Params (no secret — secrets are referenced by {file.*} placeholders and compose secret files):
  base_domain    domain of D-1; mesh domain = mesh.<base_domain>. If omitted, MG_BASE_DOMAIN is used.
  lan_ipv4       IPv4 the host publishes 80/443 on (never 0.0.0.0 — §15.4)
  public_entry_ipv4  IPv4 clients use to reach the edge (static /bootstrap-dns answer — §14.6, V-32): the LAN IP
                 in Local Development, the VPS IP once the gateway is in use (P1-T18)
  acme           "staging" or "production" (Let's Encrypt; staging first — P1-T05)
  image          edge image pinned by digest (versions.lock)
  dns_resolvers  public resolvers for the DNS-01 propagation check (split-horizon safe — P1-T06)
  admin_allow    CIDRs allowed to reach admin.<base_domain> (Platform Console — §15.4 "giới hạn IP"): private ranges
                 of the management network (staging: MG_LAN_CIDR), never the tenant pool; any other source is aborted
  tunnel         optional {"edge_tunnel_ipv4", "peer_ipv4", "http_port", "https_port"}: tunnel-facing listeners for
                 the VPS gateway (§14.6, §14.9). The edge publishes the two ports on the host's tunnel IP only and
                 REQUIRES a PROXY v2 header from the tunnel peer; a header from any other source is rejected and a
                 headerless connection from any other source is closed by the @direct_tunnel guard (GW-02, V-17).
                 app.<base_domain> and auth.<base_domain> are served there too (public through the VPS);
                 admin.<base_domain>, the Admin REST API and the master realm of the IdP never are (P2-T16) — nor,
                 therefore, the Keycloak administration console, served only on admin.<base_domain> behind the
                 forward_auth of the api (template v8, P3-T15).

From template v9 (P4-T01a) app.<base_domain> and admin.<base_domain> send every path outside /api/* (and, on admin.,
outside the Keycloak console) to the static SPA container web:8080 on mg-edge (service `web` of compose project mg-app,
tools/render_app.py); the edge is the single source of the browser security headers of both origins.

Writes <out_dir>/caddy/Caddyfile and <out_dir>/compose.edge.yaml. Output is deterministic — guarded by
tools/test_render_edge.py (golden files). Standard library only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import string
import sys

import mgenv  # noqa: E402 — tools/mgenv.py: env file of the environment (no secrets)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "9"   # 9: SPA web sau app./admin. (P4-T01a)
CADDYFILE_TMPL = ROOT / "infrastructure" / "caddy" / "Caddyfile.tmpl"
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.edge.yaml.tmpl"

DOMAIN_RE = re.compile(r"(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
IMAGE_RE = re.compile(r"^[a-z0-9.\-/]+@sha256:[0-9a-f]{64}$")
ACME = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}
# Static IPs of the edge on the shared platform networks (infrastructure/host/networks.sh: lower half of each /24,
# dynamic allocation is limited to the upper half with --ip-range).
EDGE_IPS = {"edge_ip": "10.249.0.2", "edge_admin_ip": "10.249.2.2", "edge_obs_ip": "10.249.3.2",
            # mg-idp (G2 vòng 2, A-8): edge là thành viên duy nhất cùng idp — nguồn duy nhất tới idp:8080
            "edge_idp_ip": "10.249.7.2"}
# Internal listeners (§14.6): only callers inside the matching subnet are served, everything else is aborted.
INTERNAL = {"admin_subnet": "10.249.2.0/24", "admin_port": "8081", "obs_subnet": "10.249.3.0/24", "metrics_port": "9091"}
# Static IP of the worker on mg-edge (compose project mg-app, tools/render_app.py — lower half of the /24 like the
# edge's): the only source the edge lets reach the Admin REST API and the master realm of auth.<domain> (P2-T05a).
APP_IPS = {"worker_edge_ip": "10.249.0.4"}
# Tenant network pool (versions.lock [ids] tenant_net_pool, §14.3): a source in it is aborted on the platform sites.
TENANT_POOL = "10.250.0.0/16"
REQUIRED = ["lan_ipv4", "public_entry_ipv4", "acme", "image", "dns_resolvers", "admin_allow"]


class ParamError(ValueError):
    pass


def deny_all_but(peer: str) -> list[str]:
    """CIDRs covering every IPv4 address except `peer`, plus all of IPv6 — the deny list of the proxy_protocol
    wrapper: sources in `allow` would get USE (header optional), so the peer is left to `fallback_policy require`."""
    nets = ipaddress.ip_network("0.0.0.0/0").address_exclude(ipaddress.ip_network(f"{peer}/32"))
    return [str(n) for n in sorted(nets)] + ["::/0"]


def tunnel_values(p: dict, edge_ip: str, mesh_domain: str, base_domain: str) -> dict[str, str]:
    t = p.get("tunnel")
    if not t:
        return {"tunnel_servers": "", "tunnel_tls_site": "", "tunnel_http_site": "", "tunnel_ports": "",
                "tunnel_guard": "", "tunnel_guard_matcher": "", "tunnel_guard_abort": "", "tunnel_app_site": "",
                "tunnel_auth_site": "", "tunnel_summary": "không có (Local Development, chỉ LAN-direct)"}
    tun = ipaddress.IPv4Address(t["edge_tunnel_ipv4"])
    peer = ipaddress.IPv4Address(t["peer_ipv4"])
    if not (tun.is_private and peer.is_private) or tun == peer:
        raise ParamError("tunnel addresses must be two distinct private IPv4 addresses")
    http_port, https_port = int(t.get("http_port", 8080)), int(t.get("https_port", 8443))
    if {http_port, https_port} & {80, 443, 8081, 9091} or http_port == https_port:
        raise ParamError("tunnel ports must differ from 80/443 and from the internal listener ports")
    deny = " ".join(deny_all_but(str(peer)))

    def server(port: int, tls: bool) -> str:
        lines = [f"\tservers {edge_ip}:{port} {{", "\t\tlistener_wrappers {", "\t\t\tproxy_protocol {",
                 "\t\t\t\ttimeout 5s", f"\t\t\t\tdeny {deny}", "\t\t\t\tfallback_policy require", "\t\t\t}"]
        if tls:
            lines.append("\t\t\ttls")        # TLS after PROXY protocol (GW-02)
        lines += ["\t\t}", "\t\tprotocols h1 h2"]
        if tls:
            lines.append("\t\tstrict_sni_host on")
        lines.append("\t}")
        return "\n".join(lines) + "\n"

    # proxy_protocol cannot refuse a non-peer that sends NO header: `deny` maps to REJECT, which only rejects
    # connections that carry a header (go-proxyproto), and REQUIRE would accept a forged one. A connection that did
    # carry the peer's header has the header's destination as its local address (the VPS entry, port 443/80); a
    # connection made straight to the tunnel-facing listener still has the listener port ⇒ close it (V-17, P1-T18).
    matcher = f"\t@direct_tunnel vars {{http.request.local.port}} {https_port} {http_port}\n"
    guard = ("\t# Vào thẳng listener tunnel-facing mà không qua PROXY header của VPS (địa chỉ đích còn là cổng tunnel)\n"
             "\t# ⇒ đóng kết nối, trước mọi handle khác (proxy_protocol chỉ REJECT nguồn bị deny khi chúng GỬI header).\n"
             + matcher + "\thandle @direct_tunnel {\n\t\tabort\n\t}\n")
    # auth.<domain> on the tunnel-facing listener: a site block of its own, so the routes that exist only on the
    # LAN-direct server (Admin REST API, master realm — worker only) are not even present on the server of this port —
    # whatever a PROXY header claims about the source or destination (P2-T16).
    auth_site = (
        "\n# auth." + base_domain + " trên listener tunnel-facing (public qua VPS): chỉ endpoint OIDC và trang đăng nhập\n"
        "# công khai của các realm (trừ master). Admin REST API, realm master và console KHÔNG tồn tại trên server này.\n"
        f"auth.{base_domain}:{https_port} {{\n"
        "\timport access_log\n" + matcher +
        "\timport tls_acme\n\timport platform_site\n"
        "\t@idp_public {\n\t\tpath /realms/* /resources/*\n\t\tnot path /realms/master /realms/master/*\n\t}\n"
        "\troute {\n\t\tabort @direct_tunnel\n\t\tabort @from_tenant_pool\n\t\trespond @unsafe_path 404\n"
        "\t\treverse_proxy @idp_public idp.:8080 {\n\t\t\timport upstream_headers\n\t\t}\n"
        "\t\trespond 404\n\t}\n}\n"
        # A host with no site on the TLS tunnel-facing server (admin.<domain>, or any name the edge holds a certificate
        # for) would get Caddy's default empty 200 — answered, through the VPS or straight to the port. Catch-all site of
        # lowest precedence ⇒ close the connection instead (G2: run_staging.sh tunnel-reject with SNI admin., 2026-11-17).
        # The plain-HTTP tunnel-facing listener needs none: its site `http://…, http://:<port>` already matches any host.
        "\n# Listener tunnel-facing: host không có site trên server này (admin." + base_domain + " và mọi tên khác edge có chứng\n"
        "# chỉ) ⇒ đóng kết nối, thay cho phản hồi 200 rỗng mặc định của Caddy khi không site nào khớp.\n"
        f"https://:{https_port} {{\n\tabort\n}}\n")
    return {
        "tunnel_servers": server(https_port, True) + server(http_port, False),
        "tunnel_tls_site": f", *.{mesh_domain}:{https_port}",
        "tunnel_http_site": f", http://:{http_port}",
        "tunnel_ports": f'      - "{tun}:{http_port}:{http_port}/tcp"   # tunnel-facing (VPS gateway)\n'
                        f'      - "{tun}:{https_port}:{https_port}/tcp"\n',
        "tunnel_guard": guard,
        "tunnel_guard_matcher": matcher,
        "tunnel_guard_abort": "\t\tabort @direct_tunnel\n",
        "tunnel_app_site": f", app.{base_domain}:{https_port}",
        "tunnel_auth_site": auth_site,
        "tunnel_summary": f"{edge_ip}:{https_port} (TLS) và :{http_port}, publish trên IP tunnel {tun}; "
                          f"bắt buộc PROXY v2 từ {peer}, header từ nguồn khác bị từ chối, kết nối không header "
                          f"từ nguồn khác bị đóng ở tầng HTTP (@direct_tunnel)",
    }


def validate(p: dict) -> dict:
    p = dict(p)
    p.setdefault("base_domain", os.environ.get("MG_BASE_DOMAIN", ""))
    missing = [k for k in REQUIRED if k not in p]
    if missing:
        raise ParamError(f"missing parameters: {', '.join(missing)}")
    if not DOMAIN_RE.fullmatch(p["base_domain"]):
        raise ParamError("base_domain missing or invalid (set it in params or MG_BASE_DOMAIN)")
    ip = ipaddress.IPv4Address(p["lan_ipv4"])
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ParamError("lan_ipv4 must be a unicast host address (never 0.0.0.0 — §15.4)")
    entry = ipaddress.IPv4Address(p["public_entry_ipv4"])
    if entry.is_unspecified or entry.is_loopback or entry.is_multicast or entry.is_link_local:
        raise ParamError("public_entry_ipv4 must be a unicast host address")
    if p["acme"] not in ACME:
        raise ParamError(f"acme must be one of {sorted(ACME)}")
    if not IMAGE_RE.match(p["image"]):
        raise ParamError("image must be pinned by digest")
    if not p["dns_resolvers"]:
        raise ParamError("dns_resolvers must not be empty")
    for r in p["dns_resolvers"]:
        if not ipaddress.ip_address(r).is_global:
            raise ParamError("dns_resolvers must be public resolvers (split-horizon must not break DNS-01)")
    allow = p["admin_allow"]
    if isinstance(allow, str) or not allow:
        raise ParamError("admin_allow must be a non-empty list of CIDRs (management networks)")
    tenant_pool = ipaddress.ip_network(TENANT_POOL)
    for c in allow:
        n = ipaddress.ip_network(c)   # strict: host bits set ⇒ error
        if not n.is_private or n.prefixlen < 8 or n.overlaps(tenant_pool):
            raise ParamError("admin_allow: private management networks only (at least /8), never the tenant pool")
    return p


def render(params: dict) -> dict[str, str]:
    p = validate(params)
    mesh_domain = f"mesh.{p['base_domain']}"
    v = {
        "template_version": TEMPLATE_VERSION,
        "mesh_domain": mesh_domain,
        # the domain charset is [a-z0-9.-]: only the dots need escaping (RE2 and Python re agree)
        "mesh_domain_re": mesh_domain.replace(".", r"\."),
        "acme": p["acme"],
        "acme_ca": ACME[p["acme"]],
        "dns_resolvers": " ".join(p["dns_resolvers"]),
        "lan_ipv4": p["lan_ipv4"],
        "public_entry_ipv4": p["public_entry_ipv4"],
        "image": p["image"],
        "base_domain": p["base_domain"],
        "admin_allow": " ".join(str(ipaddress.ip_network(c)) for c in p["admin_allow"]),
        "tenant_pool": TENANT_POOL,
        **EDGE_IPS,
        **INTERNAL,
        **APP_IPS,
    }
    v.update(tunnel_values(p, EDGE_IPS["edge_ip"], mesh_domain, p["base_domain"]))
    return {
        "caddy/Caddyfile": string.Template(CADDYFILE_TMPL.read_text(encoding="utf-8")).substitute(v),
        "compose.edge.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(v),
    }


def write(files: dict[str, str], out_dir: pathlib.Path) -> None:
    for rel, text in files.items():
        path = out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    try:
        files = render(mgenv.load_params(argv[1]))   # ${MG_*} from the env file of the environment
    except (ParamError, ValueError, KeyError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    write(files, pathlib.Path(argv[2]))
    print(f"rendered {len(files)} files into {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
