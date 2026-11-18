#!/usr/bin/env python3
"""Render the Host Agent of one host: compose project mg-agent and its image allowlist (P3-T02; §11.1, §14.2, §14.4).

Usage:
  python3 tools/render_agent.py <env file> <out_dir> [--agent-image <ref>]

<env file>      infrastructure/environments/<env>/<env>.env — MG_ENV, MG_BASE_DOMAIN, MG_PUBLIC_IPV4 (the public entry the
                agent writes into derp.server.ipv4 of every instance; never taken from the worker). The process
                environment overrides the file (tools/mgenv.py).
--agent-image   the agent image pinned by digest (<name>@sha256:<64 hex>) or a local image ID (sha256:<64 hex>, dev/CI).
                Default: [images.mg-agent] of versions.lock (pinned once the images workflow has built the agent).

Writes into <out_dir> (on the host: /opt/meshguard/core):
  compose.agent.yaml   from infrastructure/compose/compose.agent.yaml.tmpl
  agent/allowlist      the ONLY images a tenant instance may run: [images.mg-headscale] (the patched build) and
                       [images.headscale] (official, rollback) of versions.lock, one <repository>@sha256:<digest> per
                       line (format of agentspec.ParseAllowlist). Root-owned 0644 on the host: the worker cannot add an
                       image (§14.4).
Everything else comes from versions.lock [ids] (worker UID/GID, tenant run_uid range, tenant network pool).
tools/test_render_agent.py checks the invariants. Standard library only.
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

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "3"  # 2: MG_AGENT_HELPER_IMAGE (P3-T03); 3: backups — signing key + recovery recipient (P3-T11)
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.agent.yaml.tmpl"
VERSIONS = ROOT / "versions.lock"
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-]{1,2}[a-z0-9]+)*)+$")
DOMAIN_RE = re.compile(r"(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
ENVS = ("ci", "staging", "production")
# the Headscale images a tenant may run (allowlist), in this order
TENANT_IMAGES = ("mg-headscale", "headscale")
AGE_RECIPIENT_RE = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")
SPKI_RE = re.compile(r"^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$")  # Ed25519 SubjectPublicKeyInfo, base64 (key ceremony)
SIGNING_KEY_FILE = "/opt/meshguard/secrets/agent/manifest_signing_key"  # root:root 0400 — the key ceremony (P2-T04a)


class ParamError(ValueError):
    pass


def lock() -> dict:
    return tomllib.loads(VERSIONS.read_text(encoding="utf-8"))


def allowlist(versions: dict | None = None) -> str:
    images = (versions or lock())["images"]
    lines = ["# Sinh bởi tools/render_agent.py từ versions.lock — image Headscale mà instance tenant được chạy (§11.1, §14.4).",
             "# KHÔNG sửa tay: đổi versions.lock rồi render lại (worker không ghi được file này)."]
    for name in TENANT_IMAGES:
        e = images.get(name) or {}
        repo, digest = str(e.get("image", "")), str(e.get("index", ""))
        if not REPO_RE.match(repo) or not DIGEST_RE.match(digest):
            raise ParamError(f"versions.lock [images.{name}] chưa pin digest — không render được allowlist")
        lines.append(f"{repo}@{digest}  # [images.{name}] {e.get('tag', '')}".rstrip())
    return "\n".join(lines) + "\n"


def pinned_agent() -> str:
    e = lock().get("images", {}).get("mg-agent")
    if not e or not DIGEST_RE.match(str(e.get("index", ""))):
        raise ParamError("versions.lock chưa có [images.mg-agent] — truyền --agent-image <name>@sha256:<digest> (image do "
                         "workflow `images` build cho commit cần triển khai)")
    return f"{e['image']}@{e['index']}"


def backup_blocks(env: dict[str, str]) -> dict[str, str]:
    """Backups of the agent (P3-T11, §17.1): after the key ceremony (P2-T04a) the env file holds the recovery recipient
    and the manifest public key — the agent then gets both and the signing key as a file secret (root 0400). Before it:
    nothing (Backup/Restore refuse — STATE)."""
    rec = env.get("MG_BACKUP_RECOVERY_RECIPIENT", "").strip()
    pub = env.get("MG_BACKUP_MANIFEST_PUBKEY", "").strip()
    keys = ("backup_env", "backup_secret", "backup_secret_def")
    if not rec and not pub:
        return dict.fromkeys(keys, "")
    if "AGE-SECRET-KEY" in rec.upper():
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT chứa PRIVATE KEY — xóa ngay khỏi file tham số, không commit")
    if not AGE_RECIPIENT_RE.fullmatch(rec):
        raise ParamError("MG_BACKUP_RECOVERY_RECIPIENT phải là recipient age X25519 (age1 + 58 ký tự) — cùng với MG_BACKUP_MANIFEST_PUBKEY")
    if not all(SPKI_RE.fullmatch(k.strip()) for k in pub.split(",")):
        raise ParamError("MG_BACKUP_MANIFEST_PUBKEY phải là khóa công khai Ed25519 (SPKI, base64), phân tách bằng dấu phẩy")
    lines = ["# P3-T11: backup/restore (§17.1) — khóa ký manifest của nghi thức khóa (P2-T04a) + recipient khôi phục (DR)",
             f"MG_AGENT_BACKUP_RECOVERY_RECIPIENT: {rec}",
             f"MG_BACKUP_MANIFEST_PUBKEY: {pub}",
             "MG_AGENT_MANIFEST_SIGNING_KEY_FILE: /run/secrets/manifest_signing_key"]
    return {
        "backup_env": "".join("\n      " + x for x in lines),
        "backup_secret": "\n      - source: manifest_signing_key\n        target: manifest_signing_key",
        "backup_secret_def": f"\n  manifest_signing_key:\n    file: {SIGNING_KEY_FILE}",
    }


def render(env: dict[str, str], agent_image: str, versions: dict | None = None) -> dict[str, str]:
    if not IMAGE_RE.match(agent_image):
        raise ParamError("image agent phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
    e = env.get("MG_ENV", "")
    if e not in ENVS:
        raise ParamError(f"MG_ENV phải là một trong {', '.join(ENVS)}")
    domain = env.get("MG_BASE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ParamError("MG_BASE_DOMAIN thiếu hoặc không hợp lệ")
    ids = (versions or lock())["ids"]
    pool = ipaddress.ip_network(ids["tenant_net_pool"])
    try:
        public = ipaddress.IPv4Address(env.get("MG_PUBLIC_IPV4", ""))
    except ValueError as err:
        raise ParamError("MG_PUBLIC_IPV4 thiếu hoặc không phải IPv4 — điểm vào công khai (derp.server.ipv4)") from err
    if public in pool or public.is_loopback or public.is_unspecified or public.is_multicast or public.is_link_local:
        raise ParamError("MG_PUBLIC_IPV4 phải là địa chỉ unicast ngoài pool tenant (agentspec.Host.Check)")
    lo, _, hi = str(ids["tenant_run_uid_range"]).partition("-")
    if not (lo.isdigit() and hi.isdigit() and 1000 <= int(lo) <= int(hi)):
        raise ParamError("versions.lock [ids] tenant_run_uid_range phải là min-max")
    values = {
        "template_version": TEMPLATE_VERSION,
        "agent_image": agent_image,
        "env": e,
        "base_domain": domain,
        "public_ipv4": str(public),
        "worker_uid": str(int(ids["api_worker_uid"])),
        "worker_gid": str(int(ids["mg-sec-worker"])),
        "run_uid_range": f"{int(lo)}-{int(hi)}",
        "tenant_net_pool": str(pool),
        **backup_blocks(env),
    }
    return {
        "compose.agent.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values),
        "agent/allowlist": allowlist(versions),
    }


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = argv[1:]
    image = None
    if "--agent-image" in args:
        i = args.index("--agent-image")
        if i + 1 >= len(args):
            print(__doc__)
            return 2
        image = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print(__doc__)
        return 2
    try:
        env = mgenv.environment(pathlib.Path(args[0]))
        files = render(env, image or pinned_agent())
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
