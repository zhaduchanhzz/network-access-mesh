#!/usr/bin/env python3
"""Unit test of tools/render_monitoring.py (P3-T16): compose project mg-obs, Prometheus and Alertmanager configuration,
target list, alert drills — without Docker.

    python tools/test_render_monitoring.py            # compare against tests/golden/monitoring/*/expected
    python tools/test_render_monitoring.py --update   # rewrite the golden files after an intentional template change

Checks: golden files for three environments (staging with the internal sink, production with e-mail + Telegram + an
external webhook, the ci stack); hardening of every service (pinned image, non-root, read-only rootfs, cap_drop ALL,
no-new-privileges, RAM/PID limits, no published port, no Docker socket, no secret in the environment); the networks of
§14.3 per service (alertmanager is the only one with mg-egress next to the prober; the prober's static address on
mg-admin = MG_PROBER_URL of render_app); secrets only as files of /opt/meshguard/secrets/obs; the scrape jobs (tenant
labels from SD with honor_labels false and the exported_* labels dropped, limits, the edge's metrics listener with the
token file, probe jobs through the prober, the public entry only when it differs from the edge); Alertmanager channels
per environment (credentials only as *_file), the boot-window inhibition; refusals; the target list (same rules as the
script embedded in infrastructure/host/obs-targets.sh — both run on the same rows); every alert rule has a drill.
Standard library only.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_app  # noqa: E402
import render_edge  # noqa: E402
import render_monitoring as rm  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
GOLDEN = rm.ROOT / "tests" / "golden" / "monitoring"
IMAGES = {"prometheus": "docker.io/prom/prometheus@sha256:" + "a1" * 32,
          "alertmanager": "docker.io/prom/alertmanager@sha256:" + "a2" * 32}
PROBE = "ghcr.io/zhaduchanhzz/network-access-mesh/probe@sha256:" + "a3" * 32
NODE = "ghcr.io/zhaduchanhzz/network-access-mesh/node-exporter@sha256:" + "a4" * 32
failures = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except (rm.ParamError, ValueError) as e:
        check(True, f"{name} ({str(e).splitlines()[0][:70]})")
        return
    check(False, name, "no error raised")


def render(env: dict[str, str]) -> dict[str, str]:
    return rm.render(env, PROBE, node_exporter_image=NODE, images=IMAGES)


def services(compose: str) -> dict[str, str]:
    body = compose.split("\nservices:\n", 1)[1].split("\n# Secret dạng file", 1)[0]
    parts = re.split(r"^  ([a-z][a-z-]*):\n", body, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def networks(body: str) -> dict[str, str]:
    m = re.search(r"^    networks:\n((?:      .*\n)+)", body, re.M)
    out: dict[str, str] = {}
    for name, rest in re.findall(r"^      ([a-z][a-z-]*):(.*\n(?:        .*\n)*)", m.group(1) if m else "", re.M):
        ip = re.search(r"ipv4_address: (\S+)", rest)
        out[name] = ip.group(1) if ip else ""
    return out


# ------------------------------------------------------------------------------------------------ golden files
def golden() -> None:
    update = "--update" in sys.argv
    cases = sorted(p for p in GOLDEN.iterdir() if (p / "env.json").is_file())
    check(len(cases) == 3, "three golden cases (staging, production, ci)", str([c.name for c in cases]))
    for case in cases:
        env = json.loads((case / "env.json").read_text(encoding="utf-8"))
        files = render(env)
        exp = case / "expected"
        if update:
            for rel, text in files.items():
                (exp / rel).parent.mkdir(parents=True, exist_ok=True)
                (exp / rel).write_text(text, encoding="utf-8", newline="\n")
            print(f"updated {case.name}")
            continue
        want = {p.relative_to(exp).as_posix(): p.read_text(encoding="utf-8") for p in exp.rglob("*") if p.is_file()}
        check(set(want) == set(files) and all(files[k] == want[k] for k in files), f"{case.name}: identical to golden",
              str(sorted(k for k in files if files.get(k) != want.get(k))))
        check(files == render(env), f"{case.name}: deterministic")
        invariants(case.name, env, files)


# ------------------------------------------------------------------------------------------------ invariants
def invariants(name: str, env: dict[str, str], files: dict[str, str]) -> None:
    c = files["compose.monitoring.yaml"]
    prom = files["monitoring/prometheus/prometheus.yml"]
    am = files["monitoring/alertmanager/alertmanager.yml"]
    sink = env.get("MG_ENV") != "production" and env.get("MG_ALERT_SINK", "on") == "on"
    svcs = services(c)
    want = {"prometheus", "alertmanager", "node-exporter", "prober"} | ({"alertsink"} if sink else set())
    check(set(svcs) == want, f"{name}: services {sorted(want)}", str(sorted(svcs)))
    check("$" not in c and "$" not in am, f"{name}: no placeholder left in compose/alertmanager (compose would interpolate)")
    check("name: mg-obs" in c and "/var/run/docker.sock" not in c and "docker.sock" not in c,
          f"{name}: project mg-obs, no Docker socket")
    for s, body in svcs.items():
        image = re.search(r"^    image: (\S+)", body, re.M)
        user = re.search(r'^    user: "(\d+):(\d+)"', body, re.M)
        check(bool(image) and bool(rm.IMAGE_RE.match(image.group(1))), f"{name}/{s}: image pinned by digest")
        check(bool(user) and user.group(1) != "0", f"{name}/{s}: non-root user")
        check("<<: *hardening" in body and "ports:" not in body and "privileged" not in body and "cap_add" not in body,
              f"{name}/{s}: hardening anchor, no port, no privilege")
        check(re.search(r"^    mem_limit: ", body, re.M) is not None and re.search(r"^    pids_limit: ", body, re.M) is not None,
              f"{name}/{s}: RAM and PID limits")
        env_block = re.search(r"^    environment:\n((?:      .*\n)+)", body, re.M)
        keys = re.findall(r"^      ([A-Z][A-Z0-9_]+):", env_block.group(1) if env_block else "", re.M)
        check(not [k for k in keys if re.search(r"TOKEN|PASSWORD|SECRET|KEY", k)], f"{name}/{s}: no secret in the environment",
              str(keys))
    hard = re.search(r"^x-hardening: &hardening\n((?:  .*\n)+)", c, re.M).group(1)
    check("read_only: true" in hard and "cap_drop: [ALL]" in hard and 'no-new-privileges:true' in hard,
          f"{name}: hardening = read-only rootfs, cap_drop ALL, no-new-privileges")
    nets = {s: networks(b) for s, b in svcs.items()}
    check(nets["prometheus"] == {"mg-obs": rm.OBS_IPS["prometheus_ip"]}, f"{name}: prometheus only on mg-obs (static IP)",
          str(nets["prometheus"]))
    relay = bool(env.get("MG_ALERT_EMAIL_TO")) and not env.get("MG_ALERT_SMTP_SMARTHOST")
    check(set(nets["alertmanager"]) == {"mg-obs", "mg-egress"} | ({rm.MAIL_NETWORK} if relay else set())
          and "gw_priority: 1" in svcs["alertmanager"] and (f"\n  {rm.MAIL_NETWORK}:\n    external: true" in c) == relay,
          f"{name}: alertmanager on mg-obs + mg-egress (default route out) + network mail iff e-mail via mailrelay",
          str(nets["alertmanager"]))
    check(nets["node-exporter"] == {"mg-obs": rm.OBS_IPS["node_exporter_ip"]} and "pid: host" in svcs["node-exporter"],
          f"{name}: node-exporter only on mg-obs, pid host (§14.4 — no host network, no LAN port)")
    check(re.search(r"source: /\n        target: /host\n        read_only: true\n        bind:\n          propagation: rslave",
                    svcs["node-exporter"]) is not None, f"{name}: node-exporter mounts / read-only")
    check(nets["prober"] == {"mg-edge": "", "mg-admin": rm.PROBER_IPS["prober_admin_ip"], "mg-obs": rm.OBS_IPS["prober_obs_ip"],
                             "mg-egress": ""}, f"{name}: prober on mg-edge, mg-admin (static), mg-obs (static), mg-egress",
          str(nets["prober"]))
    check(rm.prober_url() == f"http://{rm.PROBER_IPS['prober_admin_ip']}:8080" and rm.prober_url() in c,
          f"{name}: MG_PROBER_URL documented = prober's mg-admin address")
    if sink:
        check(nets["alertsink"] == {"mg-obs": rm.OBS_IPS["alertsink_ip"]} and 'command: ["alertsink"]' in svcs["alertsink"],
              f"{name}: alertsink only on mg-obs")
    pe = re.search(r"MG_PROBE_ALLOW_TARGETS: (\S+)", svcs["prober"]).group(1).split(",")
    entry = env.get("MG_PUBLIC_IPV4")
    check(pe == [render_edge.EDGE_IPS["edge_ip"]] + ([entry] if entry else []),
          f"{name}: prober targets = the edge (+ public entry)", str(pe))
    check(f"MG_PROBE_ALLOW_CALLERS: {render_edge.INTERNAL['admin_subnet']}" in svcs["prober"] and
          f"MG_PROBE_ALLOW_SCRAPERS: {rm.OBS_IPS['prometheus_ip']}" in svcs["prober"],
          f"{name}: prober callers = mg-admin, scrapers = Prometheus only")
    secret_files = re.findall(r"^  obs_[a-z_]+: \{file: (\S+)\}", c, re.M)
    check(all(f.startswith(rm.SECRET_DIR + "/") or f == rm.MAIL_CA_DEFAULT for f in secret_files) and
          f"{rm.SECRET_DIR}/edge_metrics_token" in secret_files,
          f"{name}: secrets are files of {rm.SECRET_DIR} (+ the CA certificate of the SMTP bridge)")
    check("edge_metrics_token" in svcs["prometheus"] and "edge_metrics_token" not in svcs["alertmanager"] and
          "group_add: [\"20006\"]" in svcs["prometheus"], f"{name}: metrics token only in prometheus (group mg-sec-obs)")
    check(all(f"/textfile/{t}" in svcs["node-exporter"] for t in ("postgres", "idp", "edge", "drill")) and
          'group_add: ["20007"]' in svcs["node-exporter"], f"{name}: textfile dirs of mg-backup + drill (group mg-sec-backup)")
    # prometheus.yml
    hs = prom.split("job_name: headscale", 1)[1].split("job_name:", 1)[0]
    check("honor_labels: false" in hs and "credentials_file: /run/secrets/edge_metrics_token" in hs and
          "sample_limit: 20000" in hs and "label_limit: 64" in hs and "body_size_limit: 16MB" in hs and
          "regex: exported_.*\n        action: labeldrop" in hs, f"{name}: headscale job — SD labels authoritative, limits, token file")
    check(f"replacement: {render_edge.EDGE_IPS['edge_obs_ip']}:{render_edge.INTERNAL['metrics_port']}" in hs and
          "replacement: /instance/${1}/metrics" in hs, f"{name}: headscale through the edge's metrics listener")
    jobs = re.findall(r"^  - job_name: (\S+)", prom, re.M)
    want_jobs = ["prometheus", "alertmanager", "node", "prober"] + (["alertsink"] if sink else []) + \
        ["api", "worker", "headscale", "probe-key-edge"] + (["probe-key-public"] if entry else []) + ["probe-tls"]
    check(jobs == want_jobs, f"{name}: scrape jobs {want_jobs}", str(jobs))
    domain = env["MG_BASE_DOMAIN"]
    check(f"replacement: ${{1}}.mesh.{domain}" in prom and f'capver: ["{rm.capver()}"]' in prom and
          all(f'"{h}.{domain}"' in prom for h in ("app", "auth", "admin")), f"{name}: key probes per tenant, tls of app/auth/admin")
    check(f'targets: ["{rm.OBS_IPS["alertmanager_ip"]}:9093"]' in prom and "rule_files:\n  - /etc/prometheus/rules/*.rules.yml" in prom,
          f"{name}: alerting to the static Alertmanager, rules loaded")
    # alertmanager.yml
    check('source_matchers: [alertname="HostRebooted", drill!="1"]' in am and "TenantInstanceDown|TenantControlProbeFailed" in am,
          f"{name}: boot-window inhibition (drill series never inhibit)")
    body = "\n".join(ln.split("#", 1)[0] for ln in am.splitlines())   # configuration only, not the comments
    check(not re.search(r"(password|token|secret):\s*\S", body, re.I) and "auth_password:" not in am and "bot_token:" not in am,
          f"{name}: no credential value in alertmanager.yml")
    check((f"url: http://{rm.OBS_IPS['alertsink_ip']}:8080/v1/alerts" in am) == sink, f"{name}: sink webhook iff sink on")
    check(files["monitoring/prometheus/rules/meshguard.rules.yml"] == rm.RULES.read_text(encoding="utf-8"),
          f"{name}: rules copied verbatim")


# ------------------------------------------------------------------------------------------------ channels, refusals
def channel_checks() -> None:
    base = {"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com", "MG_PUBLIC_IPV4": "203.0.113.10"}
    # e-mail through the platform's SMTP bridge (owner 2026-11-18: Cloudflare Email Service, service mailrelay)
    am = render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com"})
    a, c = am["monitoring/alertmanager/alertmanager.yml"], am["compose.monitoring.yaml"]
    amb = services(c)["alertmanager"]
    check('smarthost: "mailrelay:587"' in a and "require_tls: true" in a and "ca_file: /run/secrets/smtp_ca" in a
          and 'from: "MeshGuard <no-reply@example.com>"' in a and "auth_password_file" not in a
          and set(networks(amb)) == {"mg-obs", "mg-egress", "mail"} and "{source: obs_smtp_ca, target: smtp_ca}" in amb
          and f"obs_smtp_ca: {{file: {rm.MAIL_CA_DEFAULT}}}" in c and "obs_smtp_password" not in c,
          "e-mail via mailrelay:587: STARTTLS with the bridge's CA, sender MeshGuard <no-reply@domain>, network mail")
    a = render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com", "MG_SMTP_FROM": "ops-alerts@example.com"})[
        "monitoring/alertmanager/alertmanager.yml"]
    check('from: "ops-alerts@example.com"' in a, "sender from MG_SMTP_FROM")
    am = render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com", "MG_ALERT_SMTP_SMARTHOST": "smtp.example.com:587",
                 "MG_ALERT_SMTP_USERNAME": "alerts@example.com"})
    a, c = am["monitoring/alertmanager/alertmanager.yml"], am["compose.monitoring.yaml"]
    check('smarthost: "smtp.example.com:587"' in a and "auth_password_file: /run/secrets/smtp_password" in a
          and "ca_file" not in a and "obs_smtp_password: {file: /opt/meshguard/secrets/obs/smtp_password}" in c
          and "mail" not in networks(services(c)["alertmanager"]),
          "another relay (MG_ALERT_SMTP_SMARTHOST): login with the password file, system roots, no network mail")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com", "MG_ALERT_SMTP_REQUIRE_TLS": "false"}),
           "mailrelay without STARTTLS is refused")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com", "MG_ALERT_SMTP_CA_FILE": "/etc/ssl/ca.crt"}),
           "a CA file outside /opt/meshguard/secrets/mail is refused for mailrelay")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com", "MG_SMTP_FROM": "MeshGuard <nobody>"}),
           "an invalid sender is refused")
    am = render({**base, "MG_ALERT_SINK": "off", "MG_ALERT_TELEGRAM_CHAT_ID": "-100123"})
    a, c = am["monitoring/alertmanager/alertmanager.yml"], am["compose.monitoring.yaml"]
    check("telegram_configs:" in a and "webhook_configs" not in a and "alertsink:" not in c and
          "{source: obs_telegram_bot_token, target: telegram_bot_token}" in c, "Telegram only: token file mounted, no sink")
    raises(lambda: render({**base, "MG_ALERT_SINK": "off"}), "no channel at all is refused")
    raises(lambda: render({**base, "MG_ENV": "production"}), "production without a channel is refused (sink off by default)")
    raises(lambda: render({**base, "MG_ALERT_SINK": "yes"}), "MG_ALERT_SINK must be on/off")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops"}), "invalid e-mail address is refused")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com",
                           "MG_ALERT_SMTP_SMARTHOST": "smtp.example.com"}), "smarthost without port is refused")
    raises(lambda: render({**base, "MG_ALERT_EMAIL_TO": "ops@example.com",
                           "MG_ALERT_SMTP_SMARTHOST": "smtp.example.com:587", "MG_ALERT_SMTP_USERNAME": "u p"}),
           "invalid SMTP username is refused")
    raises(lambda: render({**base, "MG_ALERT_TELEGRAM_CHAT_ID": "@channel"}), "non-numeric Telegram chat id is refused")
    raises(lambda: render({**base, "MG_ENV": "dev"}), "unknown MG_ENV is refused")
    raises(lambda: render({**base, "MG_BASE_DOMAIN": "Example.COM"}), "invalid domain is refused")
    raises(lambda: render({k: v for k, v in base.items() if k != "MG_PUBLIC_IPV4"}), "staging without public entry is refused")
    raises(lambda: rm.render(base, "probe:latest", node_exporter_image=NODE, images=IMAGES), "probe image by tag is refused")
    raises(lambda: rm.render(base, PROBE, node_exporter_image="node-exporter:v1", images=IMAGES),
           "node-exporter image by tag is refused")
    raises(lambda: rm.render(base, PROBE, node_exporter_image=NODE, images={**IMAGES, "prometheus": "prom/prometheus:v3"}),
           "prometheus image by tag is refused")
    same = render({**base, "MG_PUBLIC_IPV4": render_edge.EDGE_IPS["edge_ip"]})["monitoring/prometheus/prometheus.yml"]
    check("probe-key-public" not in same, "public entry = the edge (Local Development) ⇒ no duplicate public probe")
    # MG_PROBER_URL of render_app accepts exactly the prober's address of this module
    check(render_app.prober_url({"MG_PROBER_URL": rm.prober_url()}) == rm.prober_url(),
          "render_app accepts MG_PROBER_URL = render_monitoring.prober_url()")
    # versions.lock: the official images pinned, capver, own images pinned once the workflow ran
    lock = tomllib.loads(rm.VERSIONS.read_text(encoding="utf-8"))
    check(all(rm.IMAGE_RE.match(rm.pinned(k)) for k in ("prometheus", "alertmanager")) and rm.capver() == 113,
          "versions.lock pins prometheus + alertmanager by digest; [monitoring] capver 113")
    check(lock["sources"]["node-exporter"]["version"] == "v1.12.1" and "node-exporter" not in lock["images"],
          "node-exporter: built from [sources.node-exporter], the official image is not used")
    ci = (rm.ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mk = (rm.ROOT / "Makefile").read_text(encoding="utf-8")
    check(f"PROMETHEUS_IMAGE: {rm.pinned('prometheus')}" in ci and f"ALERTMANAGER_IMAGE: {rm.pinned('alertmanager')}" in ci
          and f"PROMETHEUS_IMAGE ?= {rm.pinned('prometheus')}" in mk,
          "CI job monitoring and `make monitoring-test` run promtool/amtool of the images pinned in versions.lock")
    nx = (rm.ROOT / "infrastructure" / "docker" / "node-exporter" / "Dockerfile").read_text(encoding="utf-8")
    src = lock["sources"]["node-exporter"]
    check(f"ARG NODE_EXPORTER_VERSION={src['version']}" in nx and f"ARG NODE_EXPORTER_COMMIT={src['commit']}" in nx
          and all(f"golang.org/x/{m} {v}" in src["overrides"] and f"ARG X_{m.upper()}={v}" in nx
                  for m, v in (("net", "v0.62.0"), ("crypto", "v0.58.0"), ("text", "v0.43.0")))
          and lock["images"]["golang"]["index"] in nx and lock["images"]["distroless-static"]["index"] in nx,
          "node-exporter Dockerfile = [sources.node-exporter] (version, commit, x/ overrides) on the pinned golang/distroless")
    env = mgenv.environment(rm.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
    if "mg-node-exporter" in lock["images"]:
        files = rm.render(env)
        check(rm.pinned("mg-node-exporter") in files["compose.monitoring.yaml"], "staging.env renders with every pin")
    else:
        try:
            rm.render(env, PROBE)
            check(False, "staging.env without [images.mg-node-exporter] is refused")
        except rm.ParamError as e:
            check("mg-node-exporter" in str(e), "staging.env: refused until [images.mg-node-exporter] is pinned", str(e))
    files = rm.render(env, PROBE, node_exporter_image=NODE)
    check(env["MG_PUBLIC_IPV4"] in files["compose.monitoring.yaml"] and "alertsink:" in files["compose.monitoring.yaml"],
          "staging.env renders (public entry probed, internal sink on)")
    check(render_app.prober_url(env) == rm.prober_url(), "staging.env MG_PROBER_URL = the prober's mg-admin address")


# ------------------------------------------------------------------------------------------------ targets
ROWS = [("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "mg-hs-tenant-b"),
        ("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "mg-hs-tenant-a"),
        ("33333333-3333-4333-8333-333333333333", "55555555-5555-4555-8555-555555555555", "mg-hs-tenant-a"),   # duplicate
        ("not-a-uuid", "44444444-4444-4444-8444-444444444444", "mg-hs-tenant-c"),
        ("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "mg-hs-bad--slug"),
        ("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "mg-hs-X"),
        ("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "mg-agent-helper-1")]


def target_checks() -> None:
    entries, skipped = rm.instance_targets(ROWS)
    check([e["targets"] for e in entries] == [["tenant-a"], ["tenant-b"]] and
          entries[0]["labels"] == {"slug": "tenant-a", "tenant_id": ROWS[1][0], "instance_id": ROWS[1][1]},
          "targets: one per mg-hs-<slug>, sorted, labels from the container's labels", json.dumps(entries))
    check(skipped == ["mg-hs-tenant-a", "mg-hs-tenant-c", "mg-hs-bad--slug", "mg-hs-X"],
          "targets: duplicate, bad UUID, bad slug reported; other containers ignored", str(skipped))
    script = (rm.ROOT / "infrastructure" / "host" / "obs-targets.sh").read_text(encoding="utf-8")
    code = re.search(r"python3 -I -c '\n(.*?)\n' \"\$OUT\"", script, re.S).group(1)
    with tempfile.TemporaryDirectory() as d:
        out = pathlib.Path(d) / "instances.json"
        p = subprocess.run([sys.executable, "-I", "-c", code, str(out)], input="\n".join(" ".join(r) for r in ROWS) + "\n",
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        got = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        mode_ok = os.name != "posix" or oct(out.stat().st_mode)[-3:] == "644"
        check(p.returncode == 0 and got == entries and p.stderr.count("obs-targets: ") == 4 and mode_ok,
              "obs-targets.sh: the embedded script gives the same list (and warns the same rows)", p.stderr[-300:])
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "t.json"
        rm.write_atomic(path, json.dumps(entries))
        check(json.loads(path.read_text(encoding="utf-8")) == entries and not list(pathlib.Path(d).glob(".*.tmp")),
              "targets: written atomically, no temp file left")


# ------------------------------------------------------------------------------------------------ drills
def drill_checks() -> None:
    rules = rm.RULES.read_text(encoding="utf-8")
    alerts = re.findall(r"^      - alert: (\S+)", rules, re.M)
    drilled = {a for v in rm.DRILL_ALERTS.values() for a in v}
    no_file = {"PlatformTargetDown", "PlatformBackupStatusMissing"}   # stop a component / remove a status file
    check(len(alerts) == 16 and set(alerts) == drilled | no_file and not (drilled & no_file),
          f"every alert rule has a drill ({len(drilled)} by drill file, {sorted(no_file)} by action)", str(set(alerts) ^ (drilled | no_file)))
    check(set(rm.DRILLS) == set(rm.DRILL_ALERTS), "every drill names the alerts it fires")
    for n in rm.DRILLS:
        files = rm.drill_files(n, 1_800_000_000)
        ok = all(rel.startswith("drill/") and rel.endswith(".prom") or rel == "prometheus/targets/drill-instance.json"
                 for rel in files)
        lines = [ln for text in files.values() for ln in text.splitlines() if ln and not ln.startswith("#")]
        prom_ok = all('drill="1"' in ln for ln in lines) if n != "instance" else '"drill": "1"' in files[
            "prometheus/targets/drill-instance.json"]
        check(ok and prom_ok, f"drill {n}: files under drill/ (or the fake target), every series labelled drill=1")
    with tempfile.TemporaryDirectory() as d:
        mon = pathlib.Path(d)
        rm.run_drill([n for n in rm.DRILLS if n not in rm.COUNTER_DRILLS], mon, 0)
        written = sorted(p.relative_to(mon).as_posix() for p in mon.rglob("*") if p.is_file())
        rm.clear_drills(mon)
        left = [p for p in mon.rglob("*") if p.is_file()]
        check(len(written) == len(rm.DRILLS) - len(rm.COUNTER_DRILLS) and not left, "drill writes its files, clear removes all")
    # node_exporter merges a family across textfiles only when its HELP is identical (else it drops it): the drill
    # file and the stack's synthetic status.prom use exactly the texts apps/backup writes
    src = (rm.ROOT / "apps" / "backup" / "status.go").read_text(encoding="utf-8")
    go_help = dict(re.findall(r'metric\("(meshguard_backup_[a-z_]+)", "([^"]+)"', src))
    check(go_help == rm.BACKUP_HELP, "BACKUP_HELP = the HELP texts of apps/backup status.prom", str(go_help))
    pb = rm.drill_files("platform-backup", 1_800_000_000)["drill/platform-backup.prom"]
    sp = rm.backup_status_prom("postgres", 1_700_000_000)
    helps = lambda t: dict(re.findall(r"^# HELP (\S+) (.+)$", t, re.M))  # noqa: E731
    check(all(helps(pb)[m] == rm.BACKUP_HELP[m] for m in helps(pb)) and helps(sp) == rm.BACKUP_HELP
          and 'meshguard_backup_last_success_timestamp_seconds{target="postgres"} 1700000000' in sp,
          "platform-backup drill and synthetic status.prom share apps/backup's HELP texts and format")
    check("# HELP node_boot_time_seconds Node boot time, in unixtime." in rm.drill_files("reboot", 0)["drill/reboot.prom"],
          "reboot drill: node_exporter's own HELP text")
    text = rm.drill_files("idp-login", 0, step=2)["drill/idp-login.prom"]
    check("# TYPE meshguard_idp_console_logins_total counter" in text and text.rstrip().endswith(" 2"),
          "counter drill: second sample increments")


def main() -> int:
    golden()
    if "--update" in sys.argv:
        return 0
    channel_checks()
    target_checks()
    drill_checks()
    print(f"\n{'FAIL' if failures else 'OK'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
