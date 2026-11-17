#!/usr/bin/env python3
"""Render the backend of one environment: compose project mg-app (P2-T16; §4.2, §14.2–§14.4, §16.2 of the master plan)
— api, worker and the one-shot database jobs migrate and db-bootstrap, from the images built from
infrastructure/docker/app.

Usage:
  python3 tools/render_app.py <env file> <out_dir> [--api-image <ref> --worker-image <ref>]

<env file>      infrastructure/environments/<env>/<env>.env — MG_ENV, MG_BASE_DOMAIN and, outside the ci stack, the
                addresses the SSRF-hardened IdP client must refuse on top of its built-in ranges (T-21, P2-T05a):
                MG_LAN_CIDR, MG_TUNNEL_HOST_IPV4, MG_TUNNEL_VPS_IPV4, MG_PUBLIC_IPV4. The process environment
                overrides the file (tools/mgenv.py).
--api-image / --worker-image
                images pinned by digest (<name>@sha256:<64 hex>) or local image IDs (sha256:<64 hex>, dev/CI stack),
                always given together. Default: [images.mg-api] and [images.mg-worker] of versions.lock, which must
                name the SAME commit (tag) — a worker pinned for another purpose (the key ceremony) is never paired
                with a newer api by accident.

Everything else is a design constant, not an environment value: the edge's static addresses (render_edge.EDGE_IPS,
INTERNAL) give MG_TRUSTED_PROXIES (exactly the edge's address on mg-edge), MG_EDGE_ADMIN_URL and MG_IDP_PLATFORM_ADDR;
the worker's static address on mg-edge is render_edge.APP_IPS (the only source the edge lets reach the IdP's Admin
API); MG_EGRESS_DENY_CIDRS = the Docker address pool of daemon.json, the platform and tenant pools of versions.lock
[ids], plus the environment's LAN, tunnel and public addresses.

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
from render_edge import APP_IPS, DOMAIN_RE, EDGE_IPS, INTERNAL  # noqa: E402 — the edge's and the worker's addresses

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1"
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


def pinned_images() -> tuple[str, str]:
    images = tomllib.loads(VERSIONS.read_text(encoding="utf-8")).get("images", {})
    api, worker = images.get("mg-api"), images.get("mg-worker")
    if not api or not worker:
        raise ParamError("versions.lock chưa có [images.mg-api] và [images.mg-worker] của CÙNG một commit — pin digest "
                         "sau khi workflow `images` build commit cần triển khai (P2-T16), hoặc truyền --api-image và "
                         "--worker-image")
    if api.get("tag") != worker.get("tag"):
        raise ParamError("[images.mg-api] và [images.mg-worker] không cùng commit (tag) — pin cả hai từ cùng một lượt "
                         "workflow `images`")
    return f"{api['image']}@{api['index']}", f"{worker['image']}@{worker['index']}"


def render(env: dict[str, str], api_image: str, worker_image: str) -> dict[str, str]:
    for name, ref in (("api", api_image), ("worker", worker_image)):
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
        "env": e,
        "base_domain": domain,
        "edge_ip": EDGE_IPS["edge_ip"],
        "edge_admin_url": f"http://{EDGE_IPS['edge_admin_ip']}:{INTERNAL['admin_port']}",
        "idp_platform_addr": f"{EDGE_IPS['edge_ip']}:443",
        "worker_edge_ip": APP_IPS["worker_edge_ip"],
        "egress_deny": egress_deny(env),
    }
    return {"compose.app.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values)}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = argv[1:]
    images: dict[str, str] = {}
    for flag in ("--api-image", "--worker-image"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                print(__doc__)
                return 2
            images[flag] = args[i + 1]
            del args[i:i + 2]
    if len(args) != 2 or len(images) == 1:
        print(__doc__)
        return 2
    try:
        env = mgenv.environment(pathlib.Path(args[0]))
        api, worker = (images["--api-image"], images["--worker-image"]) if images else pinned_images()
        files = render(env, api, worker)
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
