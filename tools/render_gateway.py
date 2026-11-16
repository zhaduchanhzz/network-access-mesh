#!/usr/bin/env python3
"""Render the VPS Public Gateway (project mg-gateway — P1-T17, §14.9 of the master plan).

Usage:  python tools/render_gateway.py <params.json> <out_dir>

Params (no secret): vps_public_ipv4, edge_tunnel_ipv4 (host LAN end of the WireGuard tunnel), http_port, https_port
(tunnel-facing listeners of the edge), haproxy_image, stund_image (pinned by digest — versions.lock).
Writes <out_dir>/haproxy.cfg and <out_dir>/compose.gateway.yaml. Standard library only; deterministic.
"""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import string
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "infrastructure" / "gateway"
TEMPLATE_VERSION = "1"
IMAGE_RE = re.compile(r"^[a-z0-9.\-/]+@sha256:[0-9a-f]{64}$")


class ParamError(ValueError):
    pass


def render(p: dict) -> dict[str, str]:
    for k in ("vps_public_ipv4", "edge_tunnel_ipv4", "haproxy_image", "stund_image"):
        if k not in p:
            raise ParamError(f"missing parameter {k}")
    pub = ipaddress.IPv4Address(p["vps_public_ipv4"])
    tun = ipaddress.IPv4Address(p["edge_tunnel_ipv4"])
    if not pub.is_global:
        raise ParamError("vps_public_ipv4 must be a public address")
    if not tun.is_private:
        raise ParamError("edge_tunnel_ipv4 must be a private (tunnel) address")
    for k in ("haproxy_image", "stund_image"):
        if not IMAGE_RE.match(p[k]):
            raise ParamError(f"{k} must be pinned by digest")
    v = {"template_version": TEMPLATE_VERSION, "vps_public_ipv4": str(pub), "edge_tunnel_ipv4": str(tun),
         "http_port": str(int(p.get("http_port", 8080))), "https_port": str(int(p.get("https_port", 8443))),
         "haproxy_image": p["haproxy_image"], "stund_image": p["stund_image"]}
    return {name: string.Template((TEMPLATES / f"{name}.tmpl").read_text(encoding="utf-8")).substitute(v)
            for name in ("haproxy.cfg", "compose.gateway.yaml")}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    try:
        files = render(json.loads(pathlib.Path(argv[1]).read_text(encoding="utf-8")))
    except (ParamError, ValueError, KeyError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"rendered {len(files)} files into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
