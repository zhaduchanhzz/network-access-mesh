#!/usr/bin/env python3
"""Render a Headscale instance of one tenant (P1-T07, §14.5 of the master plan).

Usage:  python tools/render_instance.py <params.json> <out_dir>

Writes <out_dir>/compose.yaml, config/config.yaml, config/bootstrap-policy.hujson, records/extra-records.json and
meta/instance.json (input of `adopt-instance`, P2-T11). Output is deterministic — guarded by
tools/test_render_instance.py (golden files). If params omit `base_domain`, the MG_BASE_DOMAIN environment variable
is used (the domain is never hard-coded — D-1). Standard library only.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import string
import sys

import mgenv  # noqa: E402 — tools/mgenv.py: env file of the environment (no secrets)
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "infrastructure" / "headscale" / "templates"
TEMPLATE_VERSION = "1"

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
RESERVED = {"app", "admin", "auth", "api", "www", "stun", "mesh", "tail"}
DOMAIN_RE = re.compile(r"(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
TENANT_NET_POOL = ipaddress.ip_network("10.250.0.0/16")
RUN_UID_RANGE = range(30000, 40000)
IMAGE_RE = re.compile(r"^[a-z0-9.\-/]+@sha256:[0-9a-f]{64}$")
REQUIRED = ["tenant_id", "instance_id", "slug", "net_cidr", "run_uid", "derp_region_id", "derp_ipv4",
            "node_expiry", "nameservers", "image", "mem_limit", "cpus", "pids_limit"]


class ParamError(ValueError):
    pass


def validate(p: dict) -> dict:
    p = dict(p)
    p.setdefault("base_domain", os.environ.get("MG_BASE_DOMAIN", ""))
    missing = [k for k in REQUIRED if k not in p]
    if missing:
        raise ParamError(f"missing parameters: {', '.join(missing)}")
    for k in ("tenant_id", "instance_id"):
        try:
            if str(uuid.UUID(p[k])) != p[k]:
                raise ValueError
        except ValueError:
            raise ParamError(f"{k} must be a canonical lowercase UUID") from None
    s = p["slug"]
    if not SLUG_RE.match(s) or "--" in s or s.startswith("xn--") or s in RESERVED:
        raise ParamError(f"invalid slug {s!r} (§14.5: regex, no '--', no 'xn--', not reserved)")
    if not DOMAIN_RE.fullmatch(p["base_domain"]):
        raise ParamError("base_domain missing or invalid (set it in params or MG_BASE_DOMAIN)")
    net = ipaddress.ip_network(p["net_cidr"])
    if net.prefixlen != 29 or not net.subnet_of(TENANT_NET_POOL):
        raise ParamError(f"net_cidr must be a /29 inside {TENANT_NET_POOL}")
    if int(p["run_uid"]) not in RUN_UID_RANGE:
        raise ParamError("run_uid must be within 30000-39999")
    if not 900 <= int(p["derp_region_id"]) <= 999:
        raise ParamError("derp_region_id must be within 900-999")
    ipaddress.IPv4Address(p["derp_ipv4"])
    if not re.fullmatch(r"[1-9]\d*h", p["node_expiry"]):
        raise ParamError("node_expiry must be a whole number of hours, e.g. 2160h (90 days)")
    if not p["nameservers"]:
        raise ParamError("nameservers must not be empty (override_local_dns needs global nameservers — RT-07)")
    for ns in p["nameservers"]:
        ipaddress.ip_address(ns)
    if not IMAGE_RE.match(p["image"]):
        raise ParamError("image must be pinned by digest")
    if not re.fullmatch(r"[1-9]\d*[mg]", str(p["mem_limit"])) or not re.fullmatch(r"\d+(\.\d+)?", str(p["cpus"])):
        raise ParamError("mem_limit like 512m, cpus like 1.0")
    if int(p["pids_limit"]) < 32:
        raise ParamError("pids_limit too low")
    return p


def render(params: dict) -> dict[str, str]:
    p = validate(params)
    v = {k: str(val) for k, val in p.items() if k != "nameservers"}
    v.update(
        template_version=TEMPLATE_VERSION,
        mesh_domain=f"mesh.{p['base_domain']}",
        tailnet_suffix=f"tail.{p['base_domain']}",
        derp_region_code=f"mg-{p['slug']}",
        derp_region_name=f"MeshGuard {p['slug']}",
        nameservers_yaml="\n".join(f"      - {ns}" for ns in p["nameservers"]),
    )
    config = string.Template((TEMPLATES / "config.yaml.tmpl").read_text(encoding="utf-8")).substitute(v)
    compose = string.Template((TEMPLATES / "compose.tenant.yaml.tmpl").read_text(encoding="utf-8")).substitute(v)
    meta = {
        "tenant_id": p["tenant_id"],
        "instance_id": p["instance_id"],
        "slug": p["slug"],
        "run_uid": int(p["run_uid"]),
        "net_cidr": p["net_cidr"],
        "template_version": TEMPLATE_VERSION,
        "config_sha256": hashlib.sha256(config.encode("utf-8")).hexdigest(),
        "image": p["image"],
    }
    return {
        "compose.yaml": compose,
        "config/config.yaml": config,
        "config/bootstrap-policy.hujson": (TEMPLATES / "bootstrap-policy.hujson").read_text(encoding="utf-8"),
        "records/extra-records.json": "[]\n",
        "meta/instance.json": json.dumps(meta, indent=2, sort_keys=True) + "\n",
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
