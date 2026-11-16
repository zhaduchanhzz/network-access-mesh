#!/usr/bin/env python3
"""Render the edge (Caddy) of one host: Caddyfile + compose project mg-edge (P1-T06, §14.4, §14.6 of the master plan).

Usage:  python tools/render_edge.py <params.json> <out_dir>

Params (no secret — secrets are referenced by {file.*} placeholders and compose secret files):
  base_domain    domain of D-1; mesh domain = mesh.<base_domain>. If omitted, MG_BASE_DOMAIN is used.
  lan_ipv4       IPv4 the host publishes 80/443 on (never 0.0.0.0 — §15.4)
  acme           "staging" or "production" (Let's Encrypt; staging first — P1-T05)
  image          edge image pinned by digest (versions.lock)
  dns_resolvers  public resolvers for the DNS-01 propagation check (split-horizon safe — P1-T06)

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

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1"
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
EDGE_IPS = {"edge_ip": "10.249.0.2", "edge_admin_ip": "10.249.2.2", "edge_obs_ip": "10.249.3.2"}
REQUIRED = ["lan_ipv4", "acme", "image", "dns_resolvers"]


class ParamError(ValueError):
    pass


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
    if p["acme"] not in ACME:
        raise ParamError(f"acme must be one of {sorted(ACME)}")
    if not IMAGE_RE.match(p["image"]):
        raise ParamError("image must be pinned by digest")
    if not p["dns_resolvers"]:
        raise ParamError("dns_resolvers must not be empty")
    for r in p["dns_resolvers"]:
        if not ipaddress.ip_address(r).is_global:
            raise ParamError("dns_resolvers must be public resolvers (split-horizon must not break DNS-01)")
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
        "image": p["image"],
        **EDGE_IPS,
    }
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
        files = render(json.loads(pathlib.Path(argv[1]).read_text(encoding="utf-8")))
    except (ParamError, ValueError, KeyError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    write(files, pathlib.Path(argv[2]))
    print(f"rendered {len(files)} files into {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
