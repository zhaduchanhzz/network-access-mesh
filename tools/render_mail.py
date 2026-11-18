#!/usr/bin/env python3
"""Outbound e-mail relay of one environment (P3-T05b-mail; owner decision 2026-11-18: Cloudflare Email Service through a
Worker): the Worker's wrangler.toml, and the shared rules that tools/render_app.py (service `mail-bridge` of mg-app, the
worker's MG_SMTP_*) and tools/render_idp.py (smtpServer of the realms → mailrelay:587) apply.

Usage:
  python3 tools/render_mail.py <env file> <out_dir>      # writes <out_dir>/wrangler.toml

<out_dir> is normally infrastructure/mail/cf-worker (wrangler.toml there is gitignored), then `npx wrangler deploy` in that
directory (docs/planning/evidence/P3-T05b-mail.md, section 6). Variables of the environment file (no secrets):
  MG_BASE_DOMAIN             the sender domain must be this domain or a subdomain (onboarded for Email Sending)
  MG_SMTP_FROM               optional, default "MeshGuard <no-reply@<MG_BASE_DOMAIN>>" ("Name <address>" or an address):
                             the relay's ONE sender — MAIL FROM and From: of the worker, of Keycloak and of Alertmanager
                             (tools/render_monitoring.py reads the same variable), and the Worker's allowed sender
  MG_MAILRELAY_WORKER_NAME   optional, default meshguard-mailrelay-<MG_ENV>: name of the Worker
  MG_MAILRELAY_URL           the deployed Worker, https://<host>/v1/send — set after `wrangler deploy`; while it is
                             unset render_app.py renders no relay (the worker then cancels e-mail notifications)
The HMAC key is never here: a file secret on the host (infrastructure/host/mail-secrets.sh) and a Worker secret.

Standard library only. tools/test_render_mail.py checks the rules.
"""
from __future__ import annotations

import os
import pathlib
import re
import string
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402 — env file of the environment (no secrets)

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1"
WRANGLER_TMPL = ROOT / "infrastructure" / "mail" / "cf-worker" / "wrangler.toml.tmpl"
VERSIONS = ROOT / "versions.lock"
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# the relay's address rule (internal/mailrelay.ValidAddress): dot-atom local part, plain ASCII
LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$")
FROM_RE = re.compile(r'^(?:([^<>"]{1,64}?) *<([^<>\s]+)>|([^<>\s"]+))$')   # "Name <address>" or a bare address
WORKER_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
URL_RE = re.compile(r"^(https|http)://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)(:\d{1,5})?/v1/send$")

# Design constants of the relay (not environment values).
MAIL_NET = {"name": "mail", "subnet": "10.249.8.0/24"}      # infrastructure/host/networks.sh — internal; the stack updates it
SMTP_HOST, SMTP_PORT = "mailrelay", 587                      # alias of the relay on `mail`, name in its certificate
SECRETS = "/opt/meshguard/secrets/mail"                      # infrastructure/host/mail-secrets.sh
# file of SECRETS → (compose secret of mg-app, target in the container): the key and the HMAC key root:mg-sec-mail 0440,
# the two certificates public (0444)
FILES = {"relay_hmac_key": "app_mail_relay_hmac_key", "tls_key": "app_mail_tls_key", "tls_cert": "app_mail_tls_cert",
         "ca.crt": "app_mail_ca"}


class ParamError(ValueError):
    pass


def mail_gid() -> int:
    return int(tomllib.loads(VERSIONS.read_text(encoding="utf-8"))["ids"]["mg-sec-mail"])


def sender(env: dict[str, str]) -> tuple[str, str]:
    """(display name, address) of the relay's one sender."""
    domain = env.get("MG_BASE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ParamError("MG_BASE_DOMAIN thiếu hoặc không hợp lệ")
    m = FROM_RE.fullmatch(env.get("MG_SMTP_FROM", "").strip() or f"MeshGuard <no-reply@{domain}>")
    if not m:
        raise ParamError('MG_SMTP_FROM phải là "Tên <địa chỉ>" hoặc một địa chỉ')
    name, addr = (m.group(1) or "MeshGuard").strip(), (m.group(2) or m.group(3)).lower()
    local, _, d = addr.rpartition("@")
    if not LOCAL_RE.fullmatch(local) or ".." in local or local.startswith(".") or local.endswith(".") \
            or not DOMAIN_RE.fullmatch(d) or not (d == domain or d.endswith("." + domain)):
        raise ParamError("MG_SMTP_FROM: địa chỉ ASCII <local>@MG_BASE_DOMAIN (hoặc subdomain) — domain đã onboard Email "
                         "Sending")
    if not NAME_RE.fullmatch(name):
        raise ParamError("MG_SMTP_FROM: tên hiển thị chỉ gồm chữ, số, khoảng trắng, . _ ( ) - (tối đa 64)")
    return name, addr


def from_header(env: dict[str, str]) -> str:
    name, addr = sender(env)
    return f"{name} <{addr}>"


def relay_url(env: dict[str, str]) -> str:
    """MG_MAILRELAY_URL ("" when unset): https://<host>[:port]/v1/send; http only on the ci stack (the fake Worker)."""
    url = env.get("MG_MAILRELAY_URL", "").strip()
    if not url:
        return ""
    m = URL_RE.fullmatch(url)
    if not m or (m.group(1) == "http" and env.get("MG_ENV") != "ci"):
        raise ParamError("MG_MAILRELAY_URL phải là https://<host>/v1/send của Worker (http chỉ ở stack ci)")
    return url


def worker_name(env: dict[str, str]) -> str:
    name = env.get("MG_MAILRELAY_WORKER_NAME", "").strip() or f"meshguard-mailrelay-{env.get('MG_ENV', '')}"
    if not WORKER_RE.fullmatch(name):
        raise ParamError("MG_MAILRELAY_WORKER_NAME: [a-z0-9-], tối đa 63 ký tự")
    return name


def render(env: dict[str, str]) -> dict[str, str]:
    if env.get("MG_ENV") not in ("staging", "production"):
        raise ParamError("Worker relay thư chỉ triển khai cho staging/production (stack ci dùng Worker giả — devserver)")
    _, addr = sender(env)
    values = {"template_version": TEMPLATE_VERSION, "env": env["MG_ENV"], "worker_name": worker_name(env),
              "senders_csv": addr, "senders_toml": f'"{addr}"'}
    return {"wrangler.toml": string.Template(WRANGLER_TMPL.read_text(encoding="utf-8")).substitute(values)}


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    if len(argv) != 3:
        print(__doc__)
        return 2
    try:
        files = render(mgenv.environment(pathlib.Path(argv[1])))
    except (ParamError, mgenv.EnvError, OSError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(argv[2])
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
