#!/usr/bin/env python3
"""Render the monitoring of one environment: compose project mg-obs (P3-T16; §14.3, §14.4, §16 of the master plan) —
prometheus, alertmanager, node-exporter, the prober (P3-T03a: RPC of the worker + /probe for Prometheus) and, unless
turned off, the internal alert sink — plus the target list and the alert drills.

Usage:
  python3 tools/render_monitoring.py <env file> <out_dir> [--probe-image <ref>] [--node-exporter-image <ref>]
  python3 tools/render_monitoring.py targets <out file>        stdin: "<tenant_id> <instance_id> <container name>" lines
  python3 tools/render_monitoring.py drill <name>… <monitoring dir> [--step <seconds>]
  python3 tools/render_monitoring.py drill clear <monitoring dir>

render   <env file> = infrastructure/environments/<env>/<env>.env (tools/mgenv.py; the process environment overrides it):
         MG_ENV, MG_BASE_DOMAIN, MG_PUBLIC_IPV4 (the public entry — required outside the ci stack), and the alert channels:
           MG_ALERT_SINK              on|off — the internal sink (webhook → alertsink on mg-obs); default on, except
                                      production (off)
           MG_ALERT_EMAIL_TO          e-mail (recipients, comma-separated; empty = off) through the platform's SMTP
                                      bridge mailrelay:587 (Cloudflare Email Service — owner 2026-11-18): STARTTLS
                                      required, CA of the bridge MG_ALERT_SMTP_CA_FILE (default
                                      /opt/meshguard/secrets/mail/ca.crt), alertmanager joins the network `mail`;
                                      sender MG_SMTP_FROM (default "MeshGuard <no-reply@<MG_BASE_DOMAIN>>").
                                      MG_ALERT_SMTP_SMARTHOST (host:port) replaces the bridge by another relay;
                                      MG_ALERT_SMTP_USERNAME (optional — the password is then the file secret
                                      obs/smtp_password), MG_ALERT_SMTP_REQUIRE_TLS (default true)
           MG_ALERT_TELEGRAM_CHAT_ID  Telegram (bot token: file secret obs/telegram_bot_token)
           MG_ALERT_WEBHOOK           on|off — an external webhook (URL, which may hold a token: file secret
                                      obs/alert_webhook_url)
         At least one channel must be on. Images: [images.prometheus], [images.alertmanager] (official, pinned) and the
         images built by the `images` workflow [images.mg-node-exporter] (node_exporter rebuilt from source —
         [sources.node-exporter]), [images.mg-probe] of versions.lock; --probe-image / --node-exporter-image: a
         digest-pinned ref or a local image ID (dev/CI stack, built from the tree).
         Writes into <out_dir> (on the host /opt/meshguard/core): compose.monitoring.yaml, monitoring/prometheus/
         prometheus.yml, monitoring/prometheus/rules/meshguard.rules.yml, monitoring/alertmanager/alertmanager.yml.
         monitoring/prometheus/targets/ (obs-targets.sh) and monitoring/drill/ are left alone.
targets  the file_sd list of the tenant instances (Prometheus jobs headscale and probe-key-*): one target per instance
         container mg-hs-<slug> — infrastructure/host/obs-targets.sh pipes `docker ps` into it. Invalid lines are skipped
         with a warning; the file is replaced atomically (0644).
drill    writes synthetic series (node-exporter textfile <monitoring dir>/drill/<name>.prom, label drill="1") or a fake
         instance target (<monitoring dir>/prometheus/targets/drill-instance.json) that fire the alert rules on purpose;
         `drill clear` removes them. Names: see DRILLS. PlatformTargetDown has no drill file: stop a scraped component.

Static addresses are design constants (like render_edge.EDGE_IPS): mg-obs .3 prometheus, .4 alertmanager,
.5 node-exporter, .6 prober, .7 alertsink; the prober on mg-admin .3 (MG_PROBER_URL of the worker — render_app.py
checks it). tools/test_render_monitoring.py checks the invariants (golden files). Standard library only.
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import string
import sys
import time
import tomllib
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402 — env file of the environment (no secrets)
from render_edge import DOMAIN_RE, EDGE_IPS, INTERNAL  # noqa: E402 — the edge's addresses

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1"
MON = ROOT / "infrastructure" / "monitoring"
COMPOSE_TMPL = ROOT / "infrastructure" / "compose" / "compose.monitoring.yaml.tmpl"
PROM_TMPL = MON / "prometheus.yml.tmpl"
AM_TMPL = MON / "alertmanager.yml.tmpl"
RULES = MON / "rules" / "meshguard.rules.yml"
VERSIONS = ROOT / "versions.lock"
IMAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$")   # name@sha256:… or a local image ID
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
ENVS = ("ci", "staging", "production")
# Static addresses on mg-obs (lower half of 10.249.3.0/24 — networks.sh limits dynamic allocation to .128/25) and of
# the prober on mg-admin (MG_PROBER_URL of the worker — P3-T05c: never the prober's name, which may resolve on mg-edge).
OBS_IPS = {"prometheus_ip": "10.249.3.3", "alertmanager_ip": "10.249.3.4", "node_exporter_ip": "10.249.3.5",
           "prober_obs_ip": "10.249.3.6", "alertsink_ip": "10.249.3.7"}
PROBER_IPS = {"prober_admin_ip": "10.249.2.3"}
PROBER_RPC_PORT = 8080
SINK_PORT = 8080
# Timing by kind of environment (design constants): the dev/CI stack drills alerts within minutes.
TIMING = {
    "ci": {"scrape_interval": "5s", "scrape_timeout": "4s", "evaluation_interval": "5s", "group_wait": "5s",
           "group_interval": "15s", "repeat_interval": "1h"},
    "default": {"scrape_interval": "30s", "scrape_timeout": "10s", "evaluation_interval": "30s", "group_wait": "30s",
                "group_interval": "5m", "repeat_interval": "4h"},
}
RETENTION = {"retention_time": "15d", "retention_size": "2GB"}
SECRET_DIR = "/opt/meshguard/secrets/obs"


class ParamError(ValueError):
    pass


def prober_url() -> str:
    """MG_PROBER_URL of the worker: the prober's static address on mg-admin (render_app.py requires exactly this)."""
    return f"http://{PROBER_IPS['prober_admin_ip']}:{PROBER_RPC_PORT}"


def lock() -> dict:
    return tomllib.loads(VERSIONS.read_text(encoding="utf-8"))


def pinned(key: str) -> str:
    img = lock().get("images", {}).get(key)
    if not img or not IMAGE_RE.match(f"{img.get('image')}@{img.get('index')}"):
        raise ParamError(f"versions.lock chưa pin [images.{key}] theo digest")
    return f"{img['image']}@{img['index']}"


def capver() -> int:
    v = lock().get("monitoring", {}).get("capver")
    if not isinstance(v, int) or not 1 <= v <= 10000:
        raise ParamError("versions.lock [monitoring] capver phải là số nguyên 1–10000 (capability version của /key — RT-09)")
    return v


def _on(env: dict[str, str], key: str, default: bool) -> bool:
    v = env.get(key, "").strip().lower()
    if not v:
        return default
    if v not in ("on", "off"):
        raise ParamError(f"{key} phải là on hoặc off")
    return v == "on"


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
FROM_RE = re.compile(r"^(?:[A-Za-z0-9 ._-]{1,64} <([^<>\s]+)>|([^<>\s]+))$")   # "Name <addr>" or "addr"
HOSTPORT_RE = re.compile(r"^[A-Za-z0-9.-]+:\d{1,5}$")
# The platform's SMTP bridge (owner's choice 2026-11-18: Cloudflare Email Service — branch `mailrelay`): service
# `mailrelay` on the internal Docker network `mail`, SMTP on 587 with STARTTLS under an internal CA whose certificate is
# a file of /opt/meshguard/secrets/mail/. Only its address and contract are used here (no code of the bridge).
MAIL_RELAY = "mailrelay:587"
MAIL_NETWORK = "mail"
MAIL_CA_DEFAULT = "/opt/meshguard/secrets/mail/ca.crt"
SECRET_PATH_RE = re.compile(r"^/opt/meshguard/secrets/[a-z0-9-]+/[A-Za-z0-9._-]+$")


class Channels:
    """The receiver of one environment: config blocks, names, alertmanager's file secrets {name: host file}, and whether
    alertmanager joins the network of the SMTP bridge."""

    def __init__(self) -> None:
        self.blocks: list[str] = []
        self.names: list[str] = []
        self.secrets: dict[str, str] = {}
        self.mail_network = False


def channels(env: dict[str, str]) -> Channels:
    ch = Channels()
    blocks, names, secrets = ch.blocks, ch.names, ch.secrets
    sink = _on(env, "MG_ALERT_SINK", env.get("MG_ENV") != "production")
    hooks: list[str] = []
    if sink:
        hooks.append(f"      - url: http://{OBS_IPS['alertsink_ip']}:{SINK_PORT}/v1/alerts   # alertsink nội bộ (mg-obs)\n"
                     "        send_resolved: true\n        max_alerts: 50")
        names.append("alertsink nội bộ (webhook, mg-obs)")
    if _on(env, "MG_ALERT_WEBHOOK", False):
        hooks.append("      - url_file: /run/secrets/alert_webhook_url   # webhook ngoài qua mg-egress (URL là secret)\n"
                     "        send_resolved: true\n        max_alerts: 50")
        names.append("webhook ngoài (obs/alert_webhook_url)")
        secrets["alert_webhook_url"] = f"{SECRET_DIR}/alert_webhook_url"
    if hooks:
        blocks.append("    webhook_configs:\n" + "\n".join(hooks))
    to = env.get("MG_ALERT_EMAIL_TO", "").strip()
    if to:
        domain = env.get("MG_BASE_DOMAIN", "")
        frm = env.get("MG_SMTP_FROM", "").strip() or f"MeshGuard <no-reply@{domain}>"
        smart = env.get("MG_ALERT_SMTP_SMARTHOST", "").strip() or MAIL_RELAY
        m = FROM_RE.fullmatch(frm)
        if not all(EMAIL_RE.fullmatch(x.strip()) for x in to.split(",")) or not m or not EMAIL_RE.fullmatch(m.group(1) or m.group(2)):
            raise ParamError("MG_ALERT_EMAIL_TO (danh sách, phẩy) và MG_SMTP_FROM (\"Tên <địa chỉ>\" hoặc địa chỉ) phải là "
                             "địa chỉ e-mail")
        if not HOSTPORT_RE.fullmatch(smart) or not 1 <= int(smart.rsplit(":", 1)[1]) <= 65535:
            raise ParamError("MG_ALERT_SMTP_SMARTHOST phải là host:port của relay SMTP")
        tls = env.get("MG_ALERT_SMTP_REQUIRE_TLS", "true").strip().lower()
        if tls not in ("true", "false"):
            raise ParamError("MG_ALERT_SMTP_REQUIRE_TLS phải là true hoặc false")
        relay = smart == MAIL_RELAY
        if relay and tls != "true":
            raise ParamError("relay mailrelay:587 chỉ nhận STARTTLS — MG_ALERT_SMTP_REQUIRE_TLS phải là true")
        ca = env.get("MG_ALERT_SMTP_CA_FILE", "").strip() or (MAIL_CA_DEFAULT if relay else "")
        if ca and (not SECRET_PATH_RE.fullmatch(ca) or (relay and not ca.startswith("/opt/meshguard/secrets/mail/"))):
            raise ParamError("MG_ALERT_SMTP_CA_FILE phải là một file trong /opt/meshguard/secrets/<thư mục>/ (relay "
                             "mailrelay: /opt/meshguard/secrets/mail/)")
        lines = ["    email_configs:", f"      - to: {json.dumps(to)}", f"        from: {json.dumps(frm)}",
                 f"        smarthost: {json.dumps(smart)}" + ("   # cầu SMTP nội bộ (network mail) → Cloudflare Email Service"
                                                             if relay else ""),
                 f"        require_tls: {tls}", "        send_resolved: true"]
        if ca:
            lines += ["        tls_config:", "          ca_file: /run/secrets/smtp_ca   # CA nội bộ của relay (chỉ chứng chỉ, không khóa)",
                      "          min_version: TLS12"]
            secrets["smtp_ca"] = ca
        ch.mail_network = relay
        user = env.get("MG_ALERT_SMTP_USERNAME", "").strip()
        if user:
            if not re.fullmatch(r"[A-Za-z0-9._%+@-]{1,128}", user):
                raise ParamError("MG_ALERT_SMTP_USERNAME không hợp lệ")
            lines += [f"        auth_username: {json.dumps(user)}",
                      "        auth_password_file: /run/secrets/smtp_password   # obs/smtp_password"]
            secrets["smtp_password"] = f"{SECRET_DIR}/smtp_password"
        blocks.append("\n".join(lines))
        names.append(f"e-mail qua {smart}")
    chat = env.get("MG_ALERT_TELEGRAM_CHAT_ID", "").strip()
    if chat:
        if not re.fullmatch(r"-?\d{1,20}", chat):
            raise ParamError("MG_ALERT_TELEGRAM_CHAT_ID phải là số (chat id)")
        blocks.append("    telegram_configs:\n      - bot_token_file: /run/secrets/telegram_bot_token   # obs/telegram_bot_token\n"
                      f"        chat_id: {chat}\n        send_resolved: true\n        parse_mode: HTML")
        names.append("Telegram")
        secrets["telegram_bot_token"] = f"{SECRET_DIR}/telegram_bot_token"
    if not blocks:
        raise ParamError("không có kênh cảnh báo nào: bật MG_ALERT_SINK hoặc cấu hình e-mail/Telegram/webhook (P3-T16)")
    return ch


def public_entry(env: dict[str, str]) -> str | None:
    v = env.get("MG_PUBLIC_IPV4", "").strip()
    if not v:
        if env.get("MG_ENV") != "ci":
            raise ParamError("thiếu MG_PUBLIC_IPV4 — điểm vào công khai mà prober probe (§14.4)")
        return None
    a = ipaddress.IPv4Address(v)
    if a.is_unspecified or a.is_loopback or a.is_multicast:
        raise ParamError("MG_PUBLIC_IPV4 không hợp lệ")
    return None if v == EDGE_IPS["edge_ip"] else v


def probe_key_job(via: str, target: str, mesh: str) -> str:
    return (f"\n  - job_name: probe-key-{via}\n"
            "    metrics_path: /probe\n"
            "    params:\n"
            "      module: [key]\n"
            f'      capver: ["{capver()}"]\n'
            "    file_sd_configs:\n"
            '      - files: ["/etc/prometheus/targets/*.json"]\n'
            "        refresh_interval: 1m\n"
            "    relabel_configs:\n"
            "      - source_labels: [slug]\n"
            '        regex: "[a-z][a-z0-9-]{1,30}[a-z0-9]"\n'
            "        action: keep\n"
            "      - source_labels: [slug]\n"
            "        target_label: __param_host\n"
            f"        replacement: ${{1}}.{mesh}\n"
            "      - target_label: __param_target\n"
            f"        replacement: {target}\n"
            "      - target_label: __address__\n"
            f"        replacement: {OBS_IPS['prober_obs_ip']}:9090\n"
            "      - source_labels: [slug]\n"
            "        target_label: instance\n"
            "      - target_label: module\n"
            "        replacement: key\n"
            "      - target_label: via\n"
            f"        replacement: {via}\n"
            "    metric_relabel_configs:\n"
            "      - regex: exported_.*\n"
            "        action: labeldrop\n")


def render(env: dict[str, str], probe_image: str | None = None, *, node_exporter_image: str | None = None,
           images: dict[str, str] | None = None) -> dict[str, str]:
    """The files of compose project mg-obs. `images` replaces versions.lock pins by key (golden tests)."""
    images = images or {}

    def img(key: str) -> str:
        ref = images.get(key) or pinned(key)
        if not IMAGE_RE.match(ref):
            raise ParamError(f"image {key} phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
        return ref

    e = env.get("MG_ENV", "")
    if e not in ENVS:
        raise ParamError(f"MG_ENV phải là một trong {', '.join(ENVS)}")
    domain = env.get("MG_BASE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(domain):
        raise ParamError("MG_BASE_DOMAIN thiếu hoặc không hợp lệ")
    probe = probe_image or img("mg-probe")
    if node_exporter_image and not IMAGE_RE.match(node_exporter_image):
        raise ParamError("image node-exporter phải pin theo digest hoặc là image ID sha256:<64 hex>")
    if not IMAGE_RE.match(probe):
        raise ParamError("image prober phải pin theo digest (<name>@sha256:<64 hex>) hoặc là image ID sha256:<64 hex>")
    mesh = f"mesh.{domain}"
    entry = public_entry(env)
    ch = channels(env)
    blocks, names, secrets = ch.blocks, ch.names, ch.secrets
    sink = _on(env, "MG_ALERT_SINK", e != "production")
    timing = TIMING["ci" if e == "ci" else "default"]
    edge_metrics = f"{EDGE_IPS['edge_obs_ip']}:{INTERNAL['metrics_port']}"
    tls_hosts = [f"{h}.{domain}" for h in ("app", "auth", "admin")]
    vias = [("edge", f"{EDGE_IPS['edge_ip']}:443")] + ([("public", f"{entry}:443")] if entry else [])
    alertsink_service = ""
    if sink:
        alertsink_service = (
            "\n  # Kênh cảnh báo NỘI BỘ của staging/dev (không gửi tới người): nhận webhook của Alertmanager, giữ 1000 thông báo\n"
            "  # gần nhất trong bộ nhớ, log mỗi cảnh báo một dòng — `docker logs mg-obs-alertsink-1`. Chỉ trên mg-obs.\n"
            "  alertsink:\n"
            "    <<: *hardening\n"
            f"    image: {probe}\n"
            '    command: ["alertsink"]\n'
            '    user: "65532:65532"\n'
            "    environment:\n"
            f"      MG_ALERTSINK_ALLOW_CALLERS: {INTERNAL['obs_subnet']}   # Alertmanager + người đọc diễn tập trên mg-obs\n"
            "    networks:\n"
            "      mg-obs:\n"
            f"        ipv4_address: {OBS_IPS['alertsink_ip']}\n"
            "    mem_limit: 64m\n"
            "    cpus: 0.25\n"
            "    pids_limit: 32\n"
            "    healthcheck:\n"
            '      test: ["CMD", "/usr/local/bin/meshguard-probe", "healthcheck"]\n'
            "      interval: 30s\n"
            "      timeout: 5s\n"
            "      retries: 3\n"
            "      start_period: 10s\n"
            "      start_interval: 2s\n")
    am_secrets = ("\n    secrets:" + "".join(f"\n      - {{source: obs_{n}, target: {n}}}" for n in sorted(secrets))
                  if secrets else "")
    values = {
        "template_version": TEMPLATE_VERSION,
        "env": e,
        "mesh_domain": mesh,
        "prometheus_image": img("prometheus"),
        "alertmanager_image": img("alertmanager"),
        "node_exporter_image": node_exporter_image or img("mg-node-exporter"),
        "probe_image": probe,
        "capver": str(capver()),
        "admin_subnet": INTERNAL["admin_subnet"],
        "probe_targets": ",".join([EDGE_IPS["edge_ip"]] + ([entry] if entry else [])),
        "prober_url": prober_url(),
        "edge_ip": EDGE_IPS["edge_ip"],
        "edge_metrics": edge_metrics,
        "alertsink_summary": " và alertsink (kênh cảnh báo nội bộ)" if sink else "",
        "alertsink_net_note": ", alertsink" if sink else "",
        "alertsink_service": alertsink_service,
        "alertsink_note": f"alertsink ({OBS_IPS['alertsink_ip']}), " if sink else "",
        "alertsink_job": (f"\n  - job_name: alertsink\n    static_configs:\n      - targets: [\"{OBS_IPS['alertsink_ip']}:9090\"]\n"
                          if sink else ""),
        "alertmanager_secrets": am_secrets,
        "alertmanager_mail_net": (f"\n      {MAIL_NETWORK}: {{}}                                    # cầu SMTP mailrelay:587 "
                                  "(e-mail cảnh báo)" if ch.mail_network else ""),
        "mail_network_def": (f"\n  {MAIL_NETWORK}:\n    external: true                    # network của cầu SMTP mailrelay"
                             if ch.mail_network else ""),
        "secret_defs": "".join(f"\n  obs_{n}: {{file: {p}}}" for n, p in sorted(secrets.items())),
        "probe_key_jobs": "".join(probe_key_job(v, t, mesh) for v, t in vias),
        "probe_vias": "; via " + ", ".join(f"{v} ({t})" for v, t in vias),
        "tls_hosts": ", ".join(tls_hosts),
        "tls_targets": ", ".join(json.dumps(h) for h in tls_hosts),
        "channels": "; ".join(names),
        "receiver_configs": "\n".join(blocks),
        **OBS_IPS, **PROBER_IPS, **timing, **RETENTION,
    }
    return {
        "compose.monitoring.yaml": string.Template(COMPOSE_TMPL.read_text(encoding="utf-8")).substitute(values),
        "monitoring/prometheus/prometheus.yml": string.Template(PROM_TMPL.read_text(encoding="utf-8")).substitute(values),
        "monitoring/prometheus/rules/meshguard.rules.yml": RULES.read_text(encoding="utf-8"),
        "monitoring/alertmanager/alertmanager.yml": string.Template(AM_TMPL.read_text(encoding="utf-8")).substitute(values),
    }


# ----------------------------------------------------------------------------------------------------------- targets
def instance_targets(rows: list[tuple[str, str, str]]) -> tuple[list[dict], list[str]]:
    """file_sd entries of the tenant instances from (tenant_id, instance_id, container name) — invalid rows skipped.
    Same rules as the script embedded in infrastructure/host/obs-targets.sh (the test compares both): a container that
    is not mg-hs-* (an agent helper carrying the labels) is ignored silently; an invalid mg-hs-* row is reported."""
    out: dict[str, dict] = {}
    skipped: list[str] = []
    for tenant, instance, name in rows:
        slug = name.removeprefix("mg-hs-") if name.startswith("mg-hs-") else ""
        try:
            t, i = str(uuid.UUID(tenant)), str(uuid.UUID(instance))
        except ValueError:
            t = i = ""
        if not SLUG_RE.fullmatch(slug) or "--" in slug or not t or not i or slug in out:
            if name.startswith("mg-hs-"):
                skipped.append(name[:80])
            continue
        out[slug] = {"targets": [slug], "labels": {"slug": slug, "tenant_id": t, "instance_id": i}}
    return [out[s] for s in sorted(out)], skipped


def write_atomic(path: pathlib.Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------------------------------------- drills
ZERO_T, ZERO_I = "00000000-0000-4000-8000-00000000d001", "00000000-0000-4000-8000-00000000d002"
DRILL_SLUG = "drill-ghost"
# HELP texts of status.prom exactly as apps/backup (status.go writeStatus) writes them — the test compares both.
BACKUP_HELP = {
    "meshguard_backup_last_success_timestamp_seconds": "End of the last successful backup (0 = never).",
    "meshguard_backup_last_success_bytes": "Encrypted size of the last successful backup set.",
    "meshguard_backup_last_attempt_success": "1 if the last attempt succeeded.",
    "meshguard_backup_consecutive_failures": "Failed attempts since the last success.",
    "meshguard_backup_max_age_seconds": "A last success older than this is overdue.",
}


def backup_status_prom(target: str, last_success: float, failures: int = 0, max_age: int = 93600,
                       last_bytes: int = 0, attempt_ok: int = 1) -> str:
    """A status.prom in the format of apps/backup (dev/CI stack: the synthetic backup states of E2E-78)."""
    values = {"meshguard_backup_last_success_timestamp_seconds": int(last_success),
              "meshguard_backup_last_success_bytes": last_bytes, "meshguard_backup_last_attempt_success": attempt_ok,
              "meshguard_backup_consecutive_failures": failures, "meshguard_backup_max_age_seconds": max_age}
    return "".join(f"# HELP {m} {h}\n# TYPE {m} gauge\n{m}{{target=\"{target}\"}} {values[m]}\n" for m, h in BACKUP_HELP.items())


def _gauge(name: str, help_: str, samples: list[tuple[dict[str, str], float]], kind: str = "gauge") -> str:
    lines = [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
    for labels, v in samples:
        lab = ",".join(f'{k}="{val}"' for k, val in sorted({**labels, "drill": "1"}.items()))
        lines.append(f"{name}{{{lab}}} {v:.0f}" if float(v).is_integer() else f"{name}{{{lab}}} {v}")
    return "\n".join(lines) + "\n"


def drill_files(name: str, now: float, step: int = 1) -> dict[str, str]:
    """Files of one drill, relative to the monitoring dir. `step` 1/2 = the two values of a counter drill."""
    ti = {"tenant_id": ZERO_T, "instance_id": ZERO_I}
    fs_help = ("Filesystem space available to non-root users in bytes.", "Filesystem size in bytes.")
    d = {
        # TenantInstanceDown + TenantControlProbeFailed: an instance that does not exist behind the edge
        "instance": {"prometheus/targets/drill-instance.json": json.dumps(
            [{"targets": [DRILL_SLUG], "labels": {"slug": DRILL_SLUG, **ti, "drill": "1"}}], indent=2) + "\n"},
        "disk": {"drill/disk.prom": _gauge("node_filesystem_avail_bytes", fs_help[0],
                                           [({"device": "drill", "fstype": "ext4", "mountpoint": "/drill"}, 1e8)])
                 + _gauge("node_filesystem_size_bytes", fs_help[1],
                          [({"device": "drill", "fstype": "ext4", "mountpoint": "/drill"}, 1e9)])},
        "cert": {"drill/cert.prom": _gauge("probe_ssl_earliest_cert_expiry", "Drill: certificate expiry, Unix seconds.",
                                           [({"instance": "drill.invalid", "module": "tls", "via": "drill"}, now + 10 * 86400)])},
        # same families as the status.prom of mg-backup (textfile collector): the HELP text must be identical, or
        # node_exporter drops the family (node_textfile_scrape_error 1, "inconsistent metric help text")
        "platform-backup": {"drill/platform-backup.prom":
                            _gauge("meshguard_backup_last_success_timestamp_seconds",
                                   BACKUP_HELP["meshguard_backup_last_success_timestamp_seconds"],
                                   [({"target": "drill"}, now - 30 * 3600)])
                            + _gauge("meshguard_backup_max_age_seconds", BACKUP_HELP["meshguard_backup_max_age_seconds"],
                                     [({"target": "drill"}, 93600)])
                            + _gauge("meshguard_backup_consecutive_failures",
                                     BACKUP_HELP["meshguard_backup_consecutive_failures"], [({"target": "drill"}, 3)])},
        "tenant-backup": {"drill/tenant-backup.prom":
                          _gauge("meshguard_instance_backup_age_seconds", "Drill: backup age.", [(ti, 3 * 86400)])
                          + _gauge("meshguard_instance_backup_max_age_seconds", "Drill: max age.", [(ti, 7200)])},
        "reconcile": {"drill/reconcile.prom": _gauge("meshguard_reconcile_drift", "Drill: drift findings.",
                                                     [({"kind": "noise_key_mismatch"}, 1), ({"kind": "network_extra_member"}, 1)])},
        "apikey": {"drill/apikey.prom": _gauge("meshguard_instance_api_key_expires_in_seconds", "Drill: API key expiry.",
                                               [(ti, 5 * 86400)])},
        "idp-login": {"drill/idp-login.prom": _gauge("meshguard_idp_console_logins_total", "Drill: console sign-ins.",
                                                     [({"outcome": "success"}, step)], "counter")},
        "idp-sync": {"drill/idp-sync.prom": _gauge("meshguard_idp_audit_sync_last_success_timestamp_seconds",
                                                   "Drill: last audit sync.", [({}, now - 3600)])},
        "notify-failed": {"drill/notify-failed.prom": _gauge("alertmanager_notifications_failed_total",
                                                             "Drill: failed notifications.", [({"integration": "drill"}, step)],
                                                             "counter")},
        "reboot": {"drill/reboot.prom": _gauge("node_boot_time_seconds", "Node boot time, in unixtime.", [({}, now - 60)])},
    }
    if name not in d:
        raise ParamError(f"drill không có: {name} (có: {', '.join(DRILLS)})")
    return d[name]


DRILLS = ("instance", "disk", "cert", "platform-backup", "tenant-backup", "reconcile", "apikey", "idp-login", "idp-sync",
          "notify-failed", "reboot")
COUNTER_DRILLS = ("idp-login", "notify-failed")   # need two samples: step 1, then step 2 after a scrape
# alert rules each drill fires (E2E-78 and the staging procedure check the sink against this)
DRILL_ALERTS = {"instance": ["TenantInstanceDown", "TenantControlProbeFailed"], "disk": ["NodeFilesystemAlmostFull"],
                "cert": ["CertificateExpiringSoon"], "platform-backup": ["PlatformBackupOverdue", "PlatformBackupFailing"],
                "tenant-backup": ["TenantBackupOverdue"], "reconcile": ["ReconcileNoiseKeyMismatch", "ReconcileSecurityDrift"],
                "apikey": ["InstanceAPIKeyExpiringSoon"], "idp-login": ["IdPConsoleLogin"], "idp-sync": ["IdPAuditSyncStale"],
                "notify-failed": ["AlertmanagerNotificationsFailing"], "reboot": ["HostRebooted"]}


def drill_paths() -> list[str]:
    return sorted({p for n in DRILLS for p in drill_files(n, 0)})


def run_drill(names: list[str], mon: pathlib.Path, step_s: float) -> None:
    now = time.time()
    for n in names:
        for rel, text in drill_files(n, now).items():
            write_atomic(mon / rel, text)
            print(f"drill {n}: wrote {mon / rel}")
    counters = [n for n in names if n in COUNTER_DRILLS]
    if counters:
        print(f"drill: counters {', '.join(counters)} — second sample in {step_s:.0f} s")
        time.sleep(step_s)
        for n in counters:
            for rel, text in drill_files(n, time.time(), step=2).items():
                write_atomic(mon / rel, text)
                print(f"drill {n}: wrote {mon / rel} (step 2)")


def clear_drills(mon: pathlib.Path) -> None:
    for rel in drill_paths():
        p = mon / rel
        if p.exists():
            p.unlink()
            print(f"drill clear: removed {p}")


# ----------------------------------------------------------------------------------------------------------- main
def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = argv[1:]
    try:
        if args[:1] == ["targets"] and len(args) == 2:
            rows = [tuple(ln.split()) for ln in sys.stdin.read().splitlines() if ln.strip()]
            entries, skipped = instance_targets([r for r in rows if len(r) == 3])
            for s in skipped + [" ".join(r)[:80] for r in rows if len(r) != 3]:
                print(f"targets: bỏ qua dòng không hợp lệ: {s}", file=sys.stderr)
            write_atomic(pathlib.Path(args[1]), json.dumps(entries, indent=2) + "\n")
            print(f"wrote {args[1]}: {len(entries)} instance(s)")
            return 0
        if args[:1] == ["drill"] and len(args) >= 3:
            step = 70.0
            if "--step" in args:
                i = args.index("--step")
                step = float(args[i + 1])
                del args[i:i + 2]
            mon = pathlib.Path(args[-1])
            names = args[1:-1]
            if names == ["clear"]:
                clear_drills(mon)
                return 0
            if names == ["all"]:
                names = list(DRILLS)
            for n in names:
                drill_files(n, 0)
            run_drill(names, mon, step)
            return 0
    except (ParamError, OSError, ValueError, IndexError) as e:
        print(f"{args[0]} failed: {e}", file=sys.stderr)
        return 1
    flags: dict[str, str] = {}
    for flag in ("--probe-image", "--node-exporter-image"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                print(__doc__)
                return 2
            flags[flag] = args[i + 1]
            del args[i:i + 2]
    if len(args) != 2:
        print(__doc__)
        return 2
    try:
        files = render(mgenv.environment(pathlib.Path(args[0])), flags.get("--probe-image"),
                       node_exporter_image=flags.get("--node-exporter-image"))
    except (ParamError, mgenv.EnvError, OSError, KeyError, ValueError) as e:
        print(f"render failed: {e}", file=sys.stderr)
        return 1
    out = pathlib.Path(args[1])
    for rel, text in files.items():
        write_atomic(out / rel, text)
        print(f"wrote {out / rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
